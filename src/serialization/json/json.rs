use std::fmt::{Display, Formatter};

pub struct JsonValue {
    pub name: String,
    pub value: ValueType
}

pub enum ValueType {
    String(String),
    Boolean(bool),
    Number(f64),
    Object(Vec<JsonValue>),
    Array(Vec<ValueType>),
    Null
}

impl Display for ValueType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ValueType::String(s) => write!(f, "\"{}\"", s),
            ValueType::Boolean(b) => write!(f, "{}", b),
            ValueType::Number(n) => write!(f, "{}", n),
            ValueType::Null => write!(f, "null"),
            ValueType::Object(_) | ValueType::Array(_) => write!(f, "..."),  // placeholder as requested
        }
    }
}

pub struct Json {
    pub values: Vec<JsonValue>
}

#[test]
fn json_test() {
    let json_data = r#"{
      "nullValue": null,
      "booleans": {
        "trueValue": true,
        "falseValue": false
      },
      "numbers": {
        "integer": 42,
        "negative": -17,
        "float": 3.14159,
        "scientific": 1.23e-4
      },
      "strings": {
        "simple": "Hello, World!",
        "empty": "",
        "withSpecialChars": "Tab\t and Newline\n",
        "withUnicode": "Hello 世界 🌍",
        "withEscapes": "Quote\" Backslash\\"
      },
      "arrays": {
        "empty": [],
        "numbers": [1, 2, 3, 4, 5],
        "mixed": [1, "two", true, null, {"key": "value"}],
        "nested": [[1, 2], [3, 4], [5, 6]]
      },
      "objects": {
        "empty": {},
        "nested": {
          "level1": {
            "level2": {
              "level3": "deep nesting"
            }
          }
        },
        "withArrays": {
          "points": [
            {"x": 1, "y": 2},
            {"x": 3, "y": 4}
          ]
        }
      }
    }"#;
}