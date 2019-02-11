#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Cache {
    Client(ClientCache),
    Server(ServerCache)
}
