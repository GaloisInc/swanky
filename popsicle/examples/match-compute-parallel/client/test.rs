use std::{
    cmp,
    convert::TryInto,
};
use scuttlebutt::{Block512};

pub fn test(ids_client: &[Vec<u8>], ids_server: &[Vec<u8>],
                    payloads_client: &[Block512], payloads_server: &[Block512]) -> (u64, u64){


    let client_len = ids_client.len();
    let server_len = ids_server.len();

    let mut weighted_payload = 0;
    let mut intersection_cardinality = 0;
    for i in 0..cmp::min(client_len, server_len){

        let id_client: &[u8] = &ids_client[i];
        let id_server: &[u8] = &ids_server[i];

        let id_client: [u8; 8] = id_client.try_into().unwrap();
        let id_server: [u8; 8] = id_server.try_into().unwrap();

        let id_client = u64::from_le_bytes(id_client);
        let id_server = u64::from_le_bytes(id_server);

        if id_client == id_server{
            let client_val = u64::from_le_bytes(payloads_client[i].prefix(8).try_into().unwrap());
            let server_val = u64::from_le_bytes(payloads_server[i].prefix(8).try_into().unwrap());
            weighted_payload = weighted_payload + client_val*server_val;
            intersection_cardinality = intersection_cardinality + 1;
        }
    }
    (weighted_payload, intersection_cardinality)
}
