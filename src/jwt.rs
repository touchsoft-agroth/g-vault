pub struct JWT {
    headers: Vec<Header>,
    claims: Vec<Claim>,
    signature: Signature
}

impl JWT {
    pub fn new() -> Self {
        JWT {
            headers: vec![],
            claims: vec![],
            signature: Signature {}
        }
    }

    pub fn add_header(&mut self, name: &str, value: &str) {
        let header = Header {
            name: name.to_string(),
            value: value.to_string()
        };

        self.headers.push(header);
    }

    pub fn get_header(&self, name: &str) -> Option<&Header>{
        self.headers
            .iter()
            .find(|header| header.name == name)
    }
}

#[test]
pub fn new_test() {
    let mut jwt = JWT::new();
    jwt.add_header("typ", "JWT");
    jwt.add_header("alg", "HS256");

    let typ_header = jwt.get_header("typ").unwrap();
    assert_eq!(typ_header.name, "typ");
    assert_eq!(typ_header.value, "JWT");

    let alg_header = jwt.get_header("alg").unwrap();
    assert_eq!(alg_header.name, "alg");
    assert_eq!(alg_header.value, "HS256");
}

#[test]
pub fn from_bytes_test() {
    // let input_string = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTY3MzM2MjgxOSwiZXhwIjoxNjczMzY2NDE5fQ.tmKUlXXsQ9X5RY8rv62G7P95BEJzlQQnAT-v9TLmC2o".as_bytes();
    //
    // let header_typ = "JWT";
    // let header_alg = "HS256";
    // let claim_sub = "123456789";
    // let claim_name = "John Doe";
    // let claim_admin = true;
    // let claim_iat = 1673362819;
    // let claim_exp = 1673366419;
    //
    //let jwt = from_bytes(input_string);

    // rest of testing here. do not fill this out
}

pub struct Header {
    pub name: String,
    pub value: String
}

pub struct Claim {

}

pub struct Signature {

}