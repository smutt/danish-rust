#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Cache {
    Client(ClientCache),
    Server(ServerCache)
}




