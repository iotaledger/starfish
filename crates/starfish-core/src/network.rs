// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use futures::{
    future::{select, select_all, Either},
    FutureExt,
};
use prometheus::IntCounter;
use rand::{prelude::ThreadRng, Rng};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::{collections::HashMap, io, net::SocketAddr, ops::Range, sync::Arc, time::Duration};
use tokio::sync::Mutex;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpListener, TcpSocket, TcpStream,
    },
    runtime::Handle,
    sync::mpsc,
    time::Instant,
};

use crate::data::Data;
use crate::types::VerifiedStatementBlock;
use crate::{
    config::NodePublicConfig,
    metrics::{print_network_address_table, Metrics},
    runtime,
    stat::HistogramSender,
    types::{AuthorityIndex, BlockReference, RoundNumber},
};

const PING_INTERVAL: Duration = Duration::from_secs(3);
// Max buffer size controls the max amount of data (in bytes) to be sent/received when sending
// batches of blocks. Based on the committee size we control the max number of transactions in a block
// We aim to send committee_size own blocks and committee_size * committee_size other blocks (encoded)
// 80*1024 transactions in blocks in one round = 40 MB pure txs data
// encoded shards could take up to 120 MB, resulting in 160 MB total
const MAX_BUFFER_SIZE: u32 = 170 * 1024 * 1024;

#[allow(unused)]
// AWS regions and their names
const REGIONS: [&str; 10] = [
    "us-east-1",      // USE1
    "us-west-1",      // USW1
    "ca-central-1",   // CAC1
    "eu-west-1",      // EUW1
    "eu-south-1",     // EUS2
    "eu-north-1",     // EUN1
    "sa-east-1",      // SAE1
    "ap-south-1",     // APS1
    "ap-southeast-1", // APSE2
    "ap-northeast-1", // APNE1
];

// RTT table for 10 AWS regions, in milliseconds.
const LATENCY_TABLE: [[u32; 10]; 10] = [
    [1, 65, 14, 68, 104, 110, 112, 201, 198, 146],
    [65, 1, 78, 127, 163, 172, 175, 226, 137, 108],
    [14, 78, 1, 67, 106, 103, 122, 189, 196, 142],
    [68, 127, 67, 1, 29, 38, 176, 125, 254, 199],
    [104, 163, 106, 29, 1, 50, 215, 143, 281, 238],
    [110, 172, 103, 38, 50, 1, 220, 148, 268, 245],
    [112, 175, 122, 176, 215, 220, 1, 299, 309, 254],
    [201, 226, 189, 125, 143, 148, 299, 1, 150, 140],
    [198, 137, 196, 254, 281, 268, 309, 150, 1, 101],
    [146, 108, 142, 199, 238, 245, 254, 140, 101, 1],
];

#[derive(Debug, Serialize, Deserialize)]
pub enum NetworkMessage {
    SubscribeBroadcastRequest(RoundNumber), // subscribe from round number excluding
    // A batch of blocks is sent
    Batch(Vec<Data<VerifiedStatementBlock>>),
    /// Request a potentially missing history of a given block (only shards are sent)
    MissingHistoryRequest(BlockReference),
    /// Request specific block (blocks with full data are sent)
    MissingParentsRequest(Vec<BlockReference>),
    /// Request a tx data for a few specific block references (only shards are sent).
    MissingTxDataRequest(Vec<BlockReference>),
}

pub struct Network {
    connection_receiver: mpsc::Receiver<Connection>,
}

pub struct Connection {
    pub peer_id: usize,
    pub sender: mpsc::Sender<NetworkMessage>,
    pub receiver: mpsc::Receiver<NetworkMessage>,
}

impl Network {
    pub async fn load(
        parameters: &NodePublicConfig,
        our_id: AuthorityIndex,
        local_addr: SocketAddr,
        metrics: Arc<Metrics>,
    ) -> Self {
        let addresses = parameters.all_network_addresses().collect::<Vec<_>>();
        print_network_address_table(&addresses);
        let mimic_latency = parameters.parameters.mimic_latency;
        Self::from_socket_addresses(
            &addresses,
            our_id as usize,
            local_addr,
            metrics,
            mimic_latency,
        )
        .await
    }

    pub fn connection_receiver(&mut self) -> &mut mpsc::Receiver<Connection> {
        &mut self.connection_receiver
    }

    pub async fn from_socket_addresses(
        addresses: &[SocketAddr],
        our_id: usize,
        local_addr: SocketAddr,
        metrics: Arc<Metrics>,
        mimic_latency: bool,
    ) -> Self {
        if our_id >= addresses.len() {
            panic!(
                "our_id {our_id} is larger then address length {}",
                addresses.len()
            );
        }
        let latency_table = generate_latency_table(addresses.len(), mimic_latency);
        let server = TcpListener::bind(local_addr)
            .await
            .expect("Failed to bind to local socket");
        let mut worker_senders: HashMap<SocketAddr, mpsc::UnboundedSender<TcpStream>> =
            HashMap::default();
        let handle = Handle::current();
        let (connection_sender, connection_receiver) = mpsc::channel(16);
        for (id, address) in addresses.iter().enumerate() {
            if id == our_id {
                continue;
            }
            let (sender, receiver) = mpsc::unbounded_channel();
            assert!(
                worker_senders.insert(*address, sender).is_none(),
                "Duplicated address {} in list",
                address
            );
            handle.spawn(
                Worker {
                    peer: *address,
                    peer_id: id,
                    connection_sender: connection_sender.clone(),
                    bind_addr: bind_addr(local_addr),
                    metrics: metrics.clone(),
                    active_immediately: id < our_id,
                    extra_connection_latency: latency_table[id][our_id],
                }
                .run(receiver),
            );
        }
        handle.spawn(
            Server {
                server,
                worker_senders,
            }
            .run(),
        );
        Self {
            connection_receiver,
        }
    }
}

#[allow(dead_code)]
fn write_extra_latency_delays(latency_delays: Vec<Vec<f64>>) -> io::Result<()> {
    // Open (or create) the file "latency_delays"
    let mut file = File::create("extra_latency_delays.log")?;

    // Write the header (optional)
    writeln!(file, "Latency Delays")?;

    // Iterate over the outer Vec<Vec<f64>> to write each inner Vec<f64> as a line in the file
    for row in latency_delays {
        let row_string: String = row
            .iter()
            .map(|x| x.to_string()) // Convert each f64 to a string
            .collect::<Vec<String>>()
            .join(", "); // Join them with a comma and space
        writeln!(file, "{}", row_string)?; // Write the row to the file
    }

    Ok(())
}

struct Server {
    server: TcpListener,
    worker_senders: HashMap<SocketAddr, mpsc::UnboundedSender<TcpStream>>,
}

impl Server {
    async fn run(self) {
        loop {
            let (socket, remote_peer) = self.server.accept().await.expect("Accept failed");
            let remote_peer = remote_to_local_port(remote_peer);
            if let Some(sender) = self.worker_senders.get(&remote_peer) {
                sender.send(socket).ok();
            } else {
                tracing::warn!("Dropping connection from unknown peer {remote_peer}");
            }
        }
    }
}

// just ignore these two functions for now :)
fn remote_to_local_port(mut remote_peer: SocketAddr) -> SocketAddr {
    match &mut remote_peer {
        SocketAddr::V4(v4) => {
            v4.set_port(v4.port() / 10);
        }
        SocketAddr::V6(v6) => {
            v6.set_port(v6.port() / 10);
        }
    }
    remote_peer
}

fn bind_addr(mut local_peer: SocketAddr) -> SocketAddr {
    match &mut local_peer {
        SocketAddr::V4(v4) => {
            v4.set_port(v4.port() * 10);
        }
        SocketAddr::V6(v6) => {
            v6.set_port(v6.port() * 10);
        }
    }
    local_peer
}

struct Worker {
    peer: SocketAddr,
    peer_id: usize,
    connection_sender: mpsc::Sender<Connection>,
    bind_addr: SocketAddr,
    metrics: Arc<Metrics>,
    active_immediately: bool,
    extra_connection_latency: f64,
}

struct WorkerConnection {
    sender: mpsc::Sender<NetworkMessage>,
    receiver: mpsc::Receiver<NetworkMessage>,
    metrics: Arc<Metrics>,
    peer_id: usize,
}

impl Worker {
    const ACTIVE_HANDSHAKE: u64 = 0xFEFE0000;
    const PASSIVE_HANDSHAKE: u64 = 0x0000AEAE;
    const MAX_BUFFER_SIZE: u32 = MAX_BUFFER_SIZE;

    async fn run(self, mut receiver: mpsc::UnboundedReceiver<TcpStream>) -> Option<()> {
        let initial_delay = if self.active_immediately {
            Duration::ZERO
        } else {
            sample_delay(Duration::from_secs(1)..Duration::from_secs(5))
        };
        let mut work = self.connect_and_handle(initial_delay, self.peer).boxed();
        loop {
            match select(work, receiver.recv().boxed()).await {
                Either::Left((_work, _receiver)) => {
                    let delay = sample_delay(Duration::from_secs(1)..Duration::from_secs(5));
                    work = self.connect_and_handle(delay, self.peer).boxed();
                }
                Either::Right((received, _work)) => {
                    if let Some(received) = received {
                        tracing::debug!("Replaced connection for {}", self.peer_id);
                        work = self.handle_passive_stream(received).boxed();
                    } else {
                        // Channel closed, server is terminated
                        return None;
                    }
                }
            }
        }
    }

    async fn connect_and_handle(&self, delay: Duration, peer: SocketAddr) -> io::Result<()> {
        // this is critical to avoid race between active and passive connections
        runtime::sleep(delay).await;
        let mut stream = loop {
            let socket = if self.bind_addr.is_ipv4() {
                TcpSocket::new_v4().unwrap()
            } else {
                TcpSocket::new_v6().unwrap()
            };
            socket.set_reuseport(true).unwrap();
            socket.bind(self.bind_addr).unwrap();
            match socket.connect(peer).await {
                Ok(stream) => break stream,
                Err(_err) => {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        };
        stream.set_nodelay(true)?;
        stream.write_u64(Self::ACTIVE_HANDSHAKE).await?;
        let handshake = stream.read_u64().await?;
        if handshake != Self::PASSIVE_HANDSHAKE {
            tracing::warn!("Invalid passive handshake: {handshake}");
            return Ok(());
        }
        let Some(connection) = self.make_connection().await else {
            // todo - pass signal to break the main loop
            return Ok(());
        };
        Self::handle_stream(stream, connection, self.extra_connection_latency).await
    }

    async fn handle_passive_stream(&self, mut stream: TcpStream) -> io::Result<()> {
        stream.set_nodelay(true)?;
        stream.write_u64(Self::PASSIVE_HANDSHAKE).await?;
        let handshake = stream.read_u64().await?;
        if handshake != Self::ACTIVE_HANDSHAKE {
            tracing::warn!("Invalid active handshake: {handshake}");
            return Ok(());
        }
        let Some(connection) = self.make_connection().await else {
            // todo - pass signal to break the main loop
            return Ok(());
        };
        Self::handle_stream(stream, connection, self.extra_connection_latency).await
    }

    async fn handle_stream(
        stream: TcpStream,
        connection: WorkerConnection,
        extra_connection_latency: f64,
    ) -> io::Result<()> {
        let WorkerConnection {
            sender,
            receiver,
            metrics,
            peer_id,
        } = connection;
        tracing::debug!("Connected to {}", peer_id);
        let (reader, writer) = stream.into_split();
        let (pong_sender, pong_receiver) = mpsc::channel(16);
        let write_fut = Self::handle_write_stream(
            writer,
            receiver,
            pong_receiver,
            metrics.connection_latency_sender.get(peer_id).expect("Can not locate connection_latency_sender metric - did you initialize metrics with correct committee?").clone(),
            metrics.bytes_sent_total.clone(),
            extra_connection_latency,
        )
        .boxed();
        let read_fut = Self::handle_read_stream(
            reader,
            sender,
            pong_sender,
            metrics.bytes_received_total.clone(),
        )
        .boxed();
        let (r, _, _) = select_all([write_fut, read_fut]).await;
        tracing::debug!("Disconnected from {}", peer_id);
        r
    }

    async fn handle_write_stream(
        writer: OwnedWriteHalf,
        mut receiver: mpsc::Receiver<NetworkMessage>,
        mut pong_receiver: mpsc::Receiver<i64>,
        latency_sender: HistogramSender<Duration>,
        bytes_sent_total: IntCounter,
        connection_latency: f64,
    ) -> io::Result<()> {
        // Use Arc and Mutex to share the writer safely across multiple tasks
        let writer = Arc::new(Mutex::new(writer));
        let start = Instant::now();

        // Spawn the first task for handling pings
        let writer_clone = Arc::clone(&writer);
        let bytes_sent_total_clone = bytes_sent_total.clone();
        let ping_task = tokio::spawn(async move {
            let mut ping_deadline = start + PING_INTERVAL;
            loop {
                tokio::time::sleep_until(ping_deadline).await;
                ping_deadline += PING_INTERVAL;

                let ping_time = start.elapsed().as_micros() as i64;
                assert!(ping_time > 0); // interval can't be 0

                let ping = encode_ping(ping_time);
                let latency = generate_latency(connection_latency);
                tokio::time::sleep(latency).await;

                if let Err(e) = writer_clone.lock().await.write_all(&ping).await {
                    tracing::error!("Failed to write ping: {e}");
                    break;
                }
                bytes_sent_total_clone.inc_by(12); // ping is 12-byte sized
            }
        });

        // Spawn the second task for handling pong responses
        let writer_clone = Arc::clone(&writer);
        let bytes_sent_total_clone = bytes_sent_total.clone();
        let pong_task = tokio::spawn(async move {
            while let Some(ping) = pong_receiver.recv().await {
                if ping == 0 {
                    tracing::warn!("Invalid ping: {ping}");
                    break;
                }
                if ping > 0 {
                    match ping.checked_neg() {
                        Some(pong) => {
                            let pong = encode_ping(pong);
                            let latency = generate_latency(connection_latency);
                            tokio::time::sleep(latency).await;

                            if let Err(e) = writer_clone.lock().await.write_all(&pong).await {
                                tracing::error!("Failed to write pong: {e}");
                                break;
                            }
                            bytes_sent_total_clone.inc_by(12); // pong is 12-byte sized
                        }
                        None => {
                            tracing::warn!("Invalid ping: {ping}");
                            break;
                        }
                    }
                } else {
                    match ping.checked_neg().and_then(|n| u64::try_from(n).ok()) {
                        Some(our_ping) => {
                            let time = start.elapsed().as_micros() as u64;
                            if let Some(delay) = time.checked_sub(our_ping) {
                                latency_sender.observe(Duration::from_micros(delay));
                            } else {
                                tracing::warn!("Invalid ping: {ping}, greater than current time");
                                break;
                            }
                        }
                        None => {
                            tracing::warn!("Invalid pong: {ping}");
                            break;
                        }
                    }
                }
                // Yield to ensure responsiveness
                tokio::task::yield_now().await;
            }
        });

        // Spawn the third task for handling message sending
        let message_task = tokio::spawn(async move {
            let mut inner_task_handles = Vec::new();

            while let Some(message) = receiver.recv().await {
                let writer = writer.clone();
                let bytes_sent_total_clone = bytes_sent_total.clone();
                let latency = generate_latency(connection_latency);

                // Spawn an inner task and collect its handle
                let handle = tokio::spawn(async move {
                    let serialized = match bincode::serialize(&message) {
                        Ok(data) => data,
                        Err(e) => {
                            tracing::error!("Serialization failed: {e}");
                            return;
                        }
                    };

                    tokio::time::sleep(latency).await;

                    if let Err(e) = async {
                        let mut writer_guard = writer.lock().await;
                        // Write the length
                        writer_guard.write_u32(serialized.len() as u32).await?;

                        bytes_sent_total_clone.inc_by(serialized.len() as u64 + 4); // u32 and serialized
                                                                                    // Write the serialized data
                        writer_guard.write_all(&serialized).await
                    }
                    .await
                    {
                        tracing::error!("Failed to write message: {e}");
                    }
                });

                inner_task_handles.push(handle);
            }

            // Await all inner tasks
            for handle in inner_task_handles {
                if let Err(e) = handle.await {
                    tracing::error!("An inner task failed: {e:?}");
                }
            }
        });

        // Wait for all tasks to complete
        let _ = tokio::try_join!(ping_task, pong_task, message_task);

        Ok(())
    }

    async fn handle_read_stream(
        mut stream: OwnedReadHalf,
        sender: mpsc::Sender<NetworkMessage>,
        pong_sender: mpsc::Sender<i64>,
        bytes_received_total: IntCounter,
    ) -> io::Result<()> {
        // stdlib has a special fast implementation for generating n-size byte vectors,
        // see impl SpecFromElem for u8
        // Note that Box::new([0u8; Self::MAX_BUFFER_SIZE as usize]); does not work with large MAX_BUFFER_SIZE
        let mut buf = vec![0u8; Self::MAX_BUFFER_SIZE as usize].into_boxed_slice();
        loop {
            let size = stream.read_u32().await?;
            if size > Self::MAX_BUFFER_SIZE {
                tracing::warn!("Invalid size: {size}");
                return Ok(());
            }
            if size == 0 {
                // ping message
                let buf = &mut buf[..PING_SIZE - 4 /*Already read size(u32)*/];
                let read = stream.read_exact(buf).await?;
                assert_eq!(read, buf.len());
                bytes_received_total.inc_by(read as u64);
                let pong = decode_ping(buf);
                if pong_sender.send(pong).await.is_err() {
                    return Ok(()); // write stream closed
                }
                continue;
            }
            let buf = &mut buf[..size as usize];
            let read = stream.read_exact(buf).await?;
            assert_eq!(read, buf.len());
            bytes_received_total.inc_by(read as u64);
            match bincode::deserialize::<NetworkMessage>(buf) {
                Ok(message) => {
                    if sender.send(message).await.is_err() {
                        // todo - pass signal to break main loop
                        return Ok(());
                    }
                }
                Err(err) => {
                    tracing::warn!("Failed to deserialize: {}", err);
                    return Ok(());
                }
            }
        }
    }

    async fn make_connection(&self) -> Option<WorkerConnection> {
        let (network_in_sender, network_in_receiver) = mpsc::channel(16);
        let (network_out_sender, network_out_receiver) = mpsc::channel(16);
        let connection = Connection {
            peer_id: self.peer_id,
            sender: network_out_sender,
            receiver: network_in_receiver,
        };
        self.connection_sender.send(connection).await.ok()?;
        Some(WorkerConnection {
            sender: network_in_sender,
            receiver: network_out_receiver,
            metrics: self.metrics.clone(),
            peer_id: self.peer_id,
        })
    }
}

/// Generates a latency table for a geodistributed network.
/// `n` is the number of nodes.
/// `seed` is a global seed used for deterministic generation.
/// If `seed == 0`, the table is initialized with all zeros.
/// expected mean latency for a quorum of nodes should be below within expected thresholds
fn generate_latency_table(n: usize, mimic_latency: bool) -> Vec<Vec<f64>> {
    let mut resulting_table = vec![vec![]; n];
    if !mimic_latency {
        for item in resulting_table.iter_mut().take(n) {
            for _j in 0..n {
                item.push(0.0)
            }
        }
    } else {
        let valid_sequence = [0, 2, 4, 6, 8, 1, 3, 5, 7, 8];
        for (i, item) in resulting_table.iter_mut().enumerate().take(n) {
            for j in 0..n {
                let index_i = i % valid_sequence.len();
                let index_j = j % valid_sequence.len();
                item.push(
                    LATENCY_TABLE[valid_sequence[index_i]][valid_sequence[index_j]] as f64 / 2.0,
                )
            }
        }
    }
    resulting_table
}

fn generate_latency(mean: f64) -> Duration {
    let mut rng = rand::thread_rng();

    // Define a constant deviation percentage (e.g., ±3% of the mean)
    let deviation_percentage = 0.03; // 3%

    // Calculate the deviation based on the mean
    let deviation = mean * deviation_percentage;

    // Generate latency by adding the random deviation to the mean
    let latency = mean + rng.gen_range(-deviation..=deviation);

    // Return the latency as a Duration (in milliseconds)
    Duration::from_millis(latency as u64)
}

fn sample_delay(range: Range<Duration>) -> Duration {
    ThreadRng::default().gen_range(range)
}

const PING_SIZE: usize = 12;
fn encode_ping(message: i64) -> [u8; PING_SIZE] {
    let mut m = [0u8; 12];
    m[4..].copy_from_slice(&message.to_le_bytes());
    m
}

fn decode_ping(message: &[u8]) -> i64 {
    let mut m = [0u8; 8];
    m.copy_from_slice(message); // asserts message.len() == 8
    i64::from_le_bytes(m)
}
