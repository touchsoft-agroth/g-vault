use super::json::{ Json, JsonValue, ValueType };

enum StructureType {
    Array,
    Object,
    Unknown
}

struct StructureNode {
    pub struct_type: StructureType,
    pub children: Vec<StructureNode>,
    pub parent: Option<Box<StructureNode>>,
    pub start_index: usize,
    pub end_index: usize
}

pub fn from_uft8(buffer: &[u8]) -> Result<Json, ()> {
    let tree = build_tree(buffer, 0);

    parse_tree(&tree)
}

fn parse_tree(root: &StructureNode) -> Result<Json, ()> {
    let mut json = Json {
        values: vec![]
    };

    let mut node_stack: Vec<&StructureNode> = vec![];
    node_stack.push(root);
    while node_stack.len() > 0 {
        let current_node = node_stack.pop().unwrap();
        match current_node.struct_type {
            StructureType::Object => {

            },
            StructureType::Array => {

            },
            StructureType::Unknown => {
                return Err(());
            }
        }
    };

    Ok(json)
}

fn parse_node(buffer: &[u8], node: &StructureNode) -> Vec<JsonValue> {
    let slice = &buffer[node.start_index..node.end_index];
    let string_content = String::from_utf8(slice.to_vec()).unwrap();
    println!("{}", string_content);

    let mut j_values: Vec<JsonValue> = vec![];
    let split_string = string_content.split(",");
    for value_string in split_string {
        println!("{}", value_string);
        let (name_raw, value) = value_string.split_once(":").unwrap();
        let name = name_raw.trim()
            .strip_prefix("\"")
            .unwrap_or("")
            .strip_suffix("\"")
            .unwrap_or("");

        // todo: this may not be enough, since 0..9 is probably ascii as well...
        if value.is_ascii() {
            // find out if it contains quotation marks or not. if yes, it's probably a string.
            // if no, probably a bool
            if value.contains("\"") {
                let str = value.trim();
                let j_value = JsonValue {
                    name: name.to_string(),
                    value: ValueType::String(str.to_string())
                };
                j_values.push(j_value);
                continue;
            }

            else {
                match value {
                    "true" => {
                        let j_value = JsonValue {
                            name: name.to_string(),
                            value: ValueType::Boolean(true)
                        };
                        j_values.push(j_value);
                        continue;
                    },
                    "false" => {
                        let j_value = JsonValue {
                            name: name.to_string(),
                            value: ValueType::Boolean(false)
                        };
                        j_values.push(j_value);
                        continue;
                    },
                    "null" => {
                        let j_value = JsonValue {
                            name: name.to_string(),
                            value: ValueType::Null
                        };
                        j_values.push(j_value);
                        continue;
                    },
                    _ => {

                    }
                }
            }
        }

        else {
            match value.parse::<f64>() {
                Ok(parsed_float) => {
                    let j_value = JsonValue {
                        name: name.to_string(),
                        value: ValueType::Number(parsed_float)
                    };
                    j_values.push(j_value);
                    continue;
                },
                Err(_) => {
                    // in this case, it is either an array or an object
                }
            }
        }
    };

    j_values
}

fn build_tree(buffer: &[u8], start_index: usize) -> StructureNode {
    let mut tree: StructureNode = StructureNode {
        struct_type: StructureType::Unknown,
        children: vec![],
        parent: None,
        start_index,
        end_index: 0
    };

    for i in start_index..buffer.len() {
        let ascii_char = buffer[i] as char;

        match ascii_char {
            '{' => {
                tree.struct_type = StructureType::Object;
                let child = build_tree(buffer, i + 1);
                tree.children.push(child);
            },
            '}' => {
                tree.end_index = i;
                return tree;
            },
            '[' => {
                tree.struct_type = StructureType::Array;
                let child = build_tree(buffer, i + 1);
                tree.children.push(child);
            },
            ']' => {
                tree.end_index = i;
                return tree;
            }
            _ => ()
        }
    };

    tree
}

#[test]
fn build_tree_test() {
    let input = br#"{"test1":true,"test2": 4.123}"#;

    let tree = build_tree(input, 0);
    assert_eq!(tree.children.len(), 1);

    for node in tree.children {
        let values = parse_node(input, &node);
        for value in values {
            println!("{} : {}", value.name, value.value)
        }
    }
}
