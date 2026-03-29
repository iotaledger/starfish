// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    fmt::{Debug, Display},
};

use aws_config::{BehaviorVersion, Region};
use aws_runtime::env_config::file::{EnvConfigFileKind, EnvConfigFiles};
use aws_sdk_ec2::{
    error::SdkError,
    meta::PKG_VERSION,
    primitives::Blob,
    types::{
        EphemeralNvmeSupport, Instance as AwsInstance, MarketType, ResourceType, SpotInstanceType,
        VolumeType,
        builders::{
            BlockDeviceMappingBuilder, EbsBlockDeviceBuilder, FilterBuilder,
            InstanceMarketOptionsRequestBuilder, SpotMarketOptionsBuilder, TagBuilder,
            TagSpecificationBuilder,
        },
    },
};
use serde::Serialize;

use super::{Instance, ServerProviderClient};
use crate::{
    error::{CloudProviderError, CloudProviderResult},
    settings::{Settings, SpotPolicy},
};

// Make a request error from an AWS error message.
impl<T> From<SdkError<T>> for CloudProviderError
where
    T: Debug + std::error::Error + Send + Sync + 'static,
{
    fn from(e: SdkError<T>) -> Self {
        Self::RequestError(format!("{:?}", e.into_source()))
    }
}

/// An AWS client.
pub struct AwsClient {
    /// The settings of the testbed.
    settings: Settings,
    /// A list of clients, one per AWS region.
    clients: HashMap<String, aws_sdk_ec2::Client>,
    /// Cached image IDs per region (populated by `prepare_deploy`).
    image_ids: HashMap<String, String>,
}

impl Display for AwsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AWS EC2 client v{}", PKG_VERSION)
    }
}

impl AwsClient {
    const UBUNTU_NAME_PATTERN: &'static str =
        "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*";
    const CANONICAL_OWNER_ID: &'static str = "099720109477";
    const DEFAULT_EBS_SIZE_GB: i32 = 500; // Default size of the EBS volume in GB.

    /// Make a new AWS client.
    pub async fn new(settings: Settings) -> Self {
        let profile_files = EnvConfigFiles::builder()
            .with_file(EnvConfigFileKind::Credentials, &settings.token_file)
            .with_contents(EnvConfigFileKind::Config, "[default]\noutput=json")
            .build();

        let mut clients = HashMap::new();
        for region in settings.regions.clone() {
            #[allow(deprecated)] // TODO: update to v2025_01_17 when ready
            let sdk_config = aws_config::defaults(BehaviorVersion::v2024_03_28())
                .region(Region::new(region.clone()))
                .profile_files(profile_files.clone())
                .load()
                .await;
            let client = aws_sdk_ec2::Client::new(&sdk_config);
            clients.insert(region, client);
        }

        Self {
            settings,
            clients,
            image_ids: HashMap::new(),
        }
    }

    /// Parse an AWS response and ignore errors if they mean a request is a
    /// duplicate.
    fn check_but_ignore_duplicates<T, E>(
        response: Result<T, SdkError<E>>,
    ) -> CloudProviderResult<()>
    where
        E: Debug + std::error::Error + Send + Sync + 'static,
    {
        if let Err(e) = response {
            let error_message = format!("{e:?}");
            if !error_message.to_lowercase().contains("duplicate") {
                return Err(e.into());
            }
        }
        Ok(())
    }

    /// Convert an AWS instance into an orchestrator instance (used in the rest
    /// of the codebase).
    fn make_instance(&self, region: String, aws_instance: &AwsInstance, spot: bool) -> Instance {
        Instance {
            id: aws_instance
                .instance_id()
                .expect("AWS instance should have an id")
                .into(),
            region,
            main_ip: aws_instance
                .public_ip_address()
                .unwrap_or("0.0.0.0") // Stopped instances do not have an ip address.
                .parse()
                .expect("AWS instance should have a valid ip"),
            private_ip: aws_instance
                .private_ip_address()
                .unwrap_or("0.0.0.0") // Stopped instances do not have an ip address.
                .parse()
                .expect("AWS instance should have a valid ip"),
            tags: vec![self.settings.testbed_id.clone()],
            specs: format!(
                "{:?}",
                aws_instance
                    .instance_type()
                    .expect("AWS instance should have a type")
            ),
            spot,
            status: format!(
                "{:?}",
                aws_instance
                    .state()
                    .expect("AWS instance should have a state")
                    .name()
                    .expect("AWS status should have a name")
            )
            .as_str()
            .into(),
            created_at: aws_instance.launch_time().map(|t| t.as_secs_f64() as i64),
        }
    }

    async fn rollback_instances(
        &self,
        client: &aws_sdk_ec2::Client,
        instances: &[Instance],
    ) -> CloudProviderResult<()> {
        if instances.is_empty() {
            return Ok(());
        }

        let instance_ids = instances
            .iter()
            .map(|instance| instance.id.clone())
            .collect();
        client
            .terminate_instances()
            .set_instance_ids(Some(instance_ids))
            .send()
            .await?;
        Ok(())
    }

    /// Check whether an error message indicates an API throttling / rate-limit
    /// error.
    fn is_throttled_request(message: &str) -> bool {
        let message = message.to_lowercase();
        message.contains("requestlimitexceeded")
            || message.contains("throttl")
            || message.contains("rate exceeded")
    }

    fn is_capacity_related_request(message: &str) -> bool {
        let message = message.to_lowercase();
        message.contains("insufficientinstancecapacity")
            || message.contains("insufficient capacity")
            || message.contains("insufficientspotinstancecapacity")
            || message.contains("maxspotinstancecountexceeded")
            || (message.contains("spot")
                && (message.contains("capacity")
                    || message.contains("unavailable")
                    || message.contains("price too low")))
    }

    fn should_retry_smaller_spot_batch_for_mixed(message: &str) -> bool {
        !Self::is_throttled_request(message) && Self::is_capacity_related_request(message)
    }

    /// Query the image id determining the os of the instances.
    /// NOTE: The image id changes depending on the region.
    async fn find_image_id(&self, client: &aws_sdk_ec2::Client) -> CloudProviderResult<String> {
        // Use a more general filter that doesn't depend on specific build dates
        let filters = [
            // Filter for Ubuntu 24.04 LTS
            FilterBuilder::default()
                .name("name")
                .values(Self::UBUNTU_NAME_PATTERN)
                .build(),
            // Only look at images from Canonical
            FilterBuilder::default()
                .name("owner-id")
                .values(Self::CANONICAL_OWNER_ID)
                .build(),
            // Only want available images
            FilterBuilder::default()
                .name("state")
                .values("available")
                .build(),
        ];

        // Query images with these filters
        let request = client.describe_images().set_filters(Some(filters.to_vec()));
        let response = request.send().await?;

        // Sort images by creation date (newest first)
        let mut images = response.images().to_vec();
        images.sort_by(|a, b| {
            let a_date = a.creation_date().unwrap_or("");
            let b_date = b.creation_date().unwrap_or("");
            b_date.cmp(a_date) // Reverse order to get newest first
        });

        // Select the newest image
        let image = images.first().ok_or_else(|| {
            CloudProviderError::RequestError("Cannot find Ubuntu 24.04 image".into())
        })?;

        image
            .image_id
            .clone()
            .ok_or_else(|| CloudProviderError::UnexpectedResponse("Image without ID".into()))
    }
    /// Create a new security group for the instance (if it doesn't already
    /// exist).
    async fn create_security_group(&self, client: &aws_sdk_ec2::Client) -> CloudProviderResult<()> {
        // Create a security group (if it doesn't already exist).
        let request = client
            .create_security_group()
            .group_name(&self.settings.testbed_id)
            .description("Allow all traffic (used for benchmarks).");

        let response = request.send().await;
        Self::check_but_ignore_duplicates(response)?;

        // Authorize all traffic on the security group.
        for protocol in ["tcp", "udp", "icmp", "icmpv6"] {
            let mut request = client
                .authorize_security_group_ingress()
                .group_name(&self.settings.testbed_id)
                .ip_protocol(protocol)
                .cidr_ip("0.0.0.0/0");
            if protocol == "icmp" || protocol == "icmpv6" {
                request = request.from_port(-1).to_port(-1);
            } else {
                request = request.from_port(0).to_port(65535);
            }

            let response = request.send().await;
            Self::check_but_ignore_duplicates(response)?;
        }
        Ok(())
    }

    /// Return the command to mount the first (standard) NVMe drive.
    fn nvme_mount_command(&self) -> Vec<String> {
        const DRIVE: &str = "nvme1n1";
        let directory = self.settings.working_dir.display();
        vec![
            format!("(sudo mkfs.ext4 -E nodiscard /dev/{DRIVE} || true)"),
            format!("sudo mkdir -p {directory}"),
            format!("(sudo mount /dev/{DRIVE} {directory} || true)"),
            format!("sudo chmod 777 -R {directory}"),
        ]
    }

    fn nvme_unmount_command(&self) -> Vec<String> {
        let directory = self.settings.working_dir.display();
        vec![format!("(sudo umount {directory} || true)")]
    }

    /// Check whether the instance type specified in the settings supports NVMe
    /// drives.
    async fn check_nvme_support(&self) -> CloudProviderResult<bool> {
        // Get the client for the first region. A given instance type should either have
        // NVMe support in all regions or in none.
        let client = match self
            .settings
            .regions
            .first()
            .and_then(|x| self.clients.get(x))
        {
            Some(client) => client,
            None => return Ok(false),
        };

        // Request storage details for the instance type specified in the settings.
        let request = client
            .describe_instance_types()
            .instance_types(self.settings.specs.as_str().into());

        // Send the request.
        let response = request.send().await?;

        // Return true if the response contains references to NVMe drives.
        if let Some(info) = response.instance_types().first() {
            if let Some(info) = info.instance_storage_info() {
                if info.nvme_support() == Some(&EphemeralNvmeSupport::Required) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}

impl ServerProviderClient for AwsClient {
    const USERNAME: &'static str = "ubuntu";

    async fn list_instances(&self) -> CloudProviderResult<Vec<Instance>> {
        let filter = FilterBuilder::default()
            .name("tag:Name")
            .values(self.settings.testbed_id.clone())
            .build();

        let mut instances = Vec::new();
        for (region, client) in &self.clients {
            let request = client.describe_instances().filters(filter.clone());
            for reservation in request.send().await?.reservations() {
                for instance in reservation.instances() {
                    let is_spot = instance
                        .instance_lifecycle()
                        .is_some_and(|l| l.as_str() == "spot");
                    instances.push(self.make_instance(region.clone(), instance, is_spot));
                }
            }
        }

        Ok(instances)
    }

    async fn instance_vcpus(&self) -> CloudProviderResult<Option<usize>> {
        let client = match self
            .settings
            .regions
            .first()
            .and_then(|x| self.clients.get(x))
        {
            Some(client) => client,
            None => return Ok(None),
        };

        let response = client
            .describe_instance_types()
            .instance_types(self.settings.specs.as_str().into())
            .send()
            .await?;

        let Some(info) = response.instance_types().first() else {
            return Ok(None);
        };
        let Some(vcpu_info) = info.v_cpu_info() else {
            return Ok(None);
        };
        Ok(vcpu_info.default_v_cpus().map(|count| count as usize))
    }

    async fn start_instances<'a, I>(&self, instances: I) -> CloudProviderResult<()>
    where
        I: Iterator<Item = &'a Instance> + Send,
    {
        let mut instance_ids = HashMap::new();
        for instance in instances {
            instance_ids
                .entry(&instance.region)
                .or_insert_with(Vec::new)
                .push(instance.id.clone());
        }

        for (region, client) in &self.clients {
            let ids = instance_ids.remove(&region.to_string());
            if ids.is_some() {
                client
                    .start_instances()
                    .set_instance_ids(ids)
                    .send()
                    .await?;
            }
        }
        Ok(())
    }

    async fn stop_instances<'a, I>(&self, instances: I) -> CloudProviderResult<()>
    where
        I: Iterator<Item = &'a Instance> + Send,
    {
        let mut instance_ids = HashMap::new();
        for instance in instances {
            instance_ids
                .entry(&instance.region)
                .or_insert_with(Vec::new)
                .push(instance.id.clone());
        }

        for (region, client) in &self.clients {
            let ids = instance_ids.remove(&region.to_string());
            if ids.is_some() {
                client.stop_instances().set_instance_ids(ids).send().await?;
            }
        }
        Ok(())
    }

    async fn create_instance<S>(&self, region: S) -> CloudProviderResult<Instance>
    where
        S: Into<String> + Serialize + Send,
    {
        let mut instances = self.create_instances(region, 1).await?;
        instances.pop().ok_or_else(|| {
            CloudProviderError::UnexpectedResponse("AWS RunInstances returned no instances".into())
        })
    }

    async fn create_instances<S>(
        &self,
        region: S,
        quantity: usize,
    ) -> CloudProviderResult<Vec<Instance>>
    where
        S: Into<String> + Serialize + Send,
    {
        let region = region.into();
        let testbed_id = &self.settings.testbed_id;
        let count = i32::try_from(quantity).map_err(|_| {
            CloudProviderError::UnexpectedResponse(format!(
                "Requested instance batch is too large for AWS API: {quantity}"
            ))
        })?;

        let client = self.clients.get(&region).ok_or_else(|| {
            CloudProviderError::RequestError(format!("Undefined region {region:?}"))
        })?;

        // Use cached image ID from prepare_deploy, or fetch on demand.
        let image_id = match self.image_ids.get(&region) {
            Some(id) => id.clone(),
            None => {
                self.create_security_group(client).await?;
                self.find_image_id(client).await?
            }
        };

        let build_request = |count: i32, spot: bool| {
            let tags = TagSpecificationBuilder::default()
                .resource_type(ResourceType::Instance)
                .tags(TagBuilder::default().key("Name").value(testbed_id).build())
                .build();
            let storage = BlockDeviceMappingBuilder::default()
                .device_name("/dev/sda1")
                .ebs(
                    EbsBlockDeviceBuilder::default()
                        .delete_on_termination(true)
                        .volume_size(Self::DEFAULT_EBS_SIZE_GB)
                        .volume_type(VolumeType::Gp2)
                        .build(),
                )
                .build();
            let mut req = client
                .run_instances()
                .image_id(&image_id)
                .instance_type(self.settings.specs.as_str().into())
                .key_name(testbed_id)
                .min_count(count)
                .max_count(count)
                .security_groups(&self.settings.testbed_id)
                .block_device_mappings(storage)
                .tag_specifications(tags);
            if spot {
                let spot_options = SpotMarketOptionsBuilder::default()
                    .spot_instance_type(SpotInstanceType::OneTime)
                    .build();
                let market_options = InstanceMarketOptionsRequestBuilder::default()
                    .market_type(MarketType::Spot)
                    .spot_options(spot_options)
                    .build();
                req = req.instance_market_options(market_options);
            }
            req
        };

        let use_spot = matches!(self.settings.spot, SpotPolicy::Spot | SpotPolicy::Mixed);
        if self.settings.spot == SpotPolicy::Mixed {
            let mut pending_spot_batches = vec![quantity];
            let mut on_demand_quantity = 0usize;
            let mut instances = Vec::with_capacity(quantity);

            while let Some(batch_size) = pending_spot_batches.pop() {
                let batch_count = i32::try_from(batch_size).map_err(|_| {
                    CloudProviderError::UnexpectedResponse(format!(
                        "Requested instance batch is too large for AWS API: {batch_size}"
                    ))
                })?;

                match build_request(batch_count, true).send().await {
                    Ok(response) => {
                        let mut created = response
                            .instances()
                            .iter()
                            .map(|instance| self.make_instance(region.clone(), instance, true))
                            .collect::<Vec<_>>();
                        if created.is_empty() {
                            return Err(CloudProviderError::UnexpectedResponse(
                                "AWS RunInstances returned no instances".into(),
                            ));
                        }
                        instances.append(&mut created);
                    }
                    Err(error) => {
                        let error_message = format!("{error:?}");
                        if Self::should_retry_smaller_spot_batch_for_mixed(&error_message)
                            && batch_size > 1
                        {
                            let left = batch_size / 2;
                            let right = batch_size - left;
                            eprintln!(
                                "Spot request for {batch_size} instance(s) in \
                                 {region} failed, splitting into {left} and \
                                 {right}: {error}"
                            );
                            pending_spot_batches.push(right);
                            pending_spot_batches.push(left);
                            continue;
                        }

                        if Self::should_retry_smaller_spot_batch_for_mixed(&error_message) {
                            eprintln!(
                                "Spot request failed for the last instance in \
                                 {region}, reserving it for on-demand \
                                 fallback: {error}"
                            );
                            on_demand_quantity += batch_size;
                            continue;
                        }

                        let original_error: CloudProviderError = error.into();
                        if let Err(rollback_error) =
                            self.rollback_instances(client, &instances).await
                        {
                            return Err(CloudProviderError::RequestError(format!(
                                "{original_error}; rollback of {} \
                                     partially created instance(s) \
                                     failed: {rollback_error}",
                                instances.len()
                            )));
                        }
                        return Err(original_error);
                    }
                }
            }

            if on_demand_quantity > 0 {
                let on_demand_count = i32::try_from(on_demand_quantity).map_err(|_| {
                    CloudProviderError::UnexpectedResponse(format!(
                        "Requested instance batch is too large for AWS API: {on_demand_quantity}"
                    ))
                })?;
                eprintln!(
                    "Retrying {on_demand_quantity} instance(s) in {region} \
                     as on-demand after spot halving"
                );
                let response = match build_request(on_demand_count, false).send().await {
                    Ok(response) => response,
                    Err(error) => {
                        let original_error: CloudProviderError = error.into();
                        if let Err(rollback_error) =
                            self.rollback_instances(client, &instances).await
                        {
                            return Err(CloudProviderError::RequestError(format!(
                                "{original_error}; rollback of {} \
                                     partially created instance(s) \
                                     failed: {rollback_error}",
                                instances.len()
                            )));
                        }
                        return Err(original_error);
                    }
                };
                let mut created = response
                    .instances()
                    .iter()
                    .map(|instance| self.make_instance(region.clone(), instance, false))
                    .collect::<Vec<_>>();
                if created.is_empty() {
                    return Err(CloudProviderError::UnexpectedResponse(
                        "AWS RunInstances returned no instances".into(),
                    ));
                }
                instances.append(&mut created);
            }

            return Ok(instances);
        }

        let response = build_request(count, use_spot).send().await?;
        let instances = response
            .instances()
            .iter()
            .map(|instance| self.make_instance(region.clone(), instance, use_spot))
            .collect::<Vec<_>>();
        if instances.is_empty() {
            return Err(CloudProviderError::UnexpectedResponse(
                "AWS RunInstances returned no instances".into(),
            ));
        }
        Ok(instances)
    }

    async fn delete_instance(&self, instance: Instance) -> CloudProviderResult<()> {
        let client = self.clients.get(&instance.region).ok_or_else(|| {
            CloudProviderError::RequestError(format!("Undefined region {:?}", instance.region))
        })?;

        client
            .terminate_instances()
            .set_instance_ids(Some(vec![instance.id.clone()]))
            .send()
            .await?;

        Ok(())
    }

    async fn delete_instances(&self, instances: Vec<Instance>) -> CloudProviderResult<()> {
        // Group instance IDs by region for batched API calls.
        let mut ids_by_region: HashMap<String, Vec<String>> = HashMap::new();
        for instance in instances {
            ids_by_region
                .entry(instance.region)
                .or_default()
                .push(instance.id);
        }

        for (region, ids) in ids_by_region {
            let client = self.clients.get(&region).ok_or_else(|| {
                CloudProviderError::RequestError(format!("Undefined region {region:?}"))
            })?;
            client
                .terminate_instances()
                .set_instance_ids(Some(ids))
                .send()
                .await?;
        }
        Ok(())
    }

    async fn register_ssh_public_key(&self, public_key: String) -> CloudProviderResult<()> {
        for client in self.clients.values() {
            let request = client
                .import_key_pair()
                .key_name(&self.settings.testbed_id)
                .public_key_material(Blob::new::<String>(public_key.clone()));

            let response = request.send().await;
            Self::check_but_ignore_duplicates(response)?;
        }
        Ok(())
    }

    async fn instance_setup_commands(&self) -> CloudProviderResult<Vec<String>> {
        if self.settings.nvme && self.check_nvme_support().await? {
            Ok(self.nvme_mount_command())
        } else {
            Ok(self.nvme_unmount_command())
        }
    }

    async fn prepare_deploy(&mut self) -> CloudProviderResult<()> {
        for (region, client) in &self.clients {
            self.create_security_group(client).await?;
            let image_id = self.find_image_id(client).await?;
            self.image_ids.insert(region.clone(), image_id);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::AwsClient;

    #[test]
    fn mixed_spot_fallback_skips_throttling_errors() {
        assert!(!AwsClient::should_retry_smaller_spot_batch_for_mixed(
            "RequestLimitExceeded: request limit exceeded"
        ));
        assert!(!AwsClient::should_retry_smaller_spot_batch_for_mixed(
            "ThrottlingException: Rate exceeded"
        ));
    }

    #[test]
    fn mixed_spot_halving_keeps_capacity_errors() {
        assert!(AwsClient::should_retry_smaller_spot_batch_for_mixed(
            "InsufficientSpotInstanceCapacity: no spot capacity"
        ));
        assert!(AwsClient::should_retry_smaller_spot_batch_for_mixed(
            "MaxSpotInstanceCountExceeded: too many spot requests"
        ));
        assert!(AwsClient::should_retry_smaller_spot_batch_for_mixed(
            "InsufficientInstanceCapacity: Insufficient capacity."
        ));
    }
}
