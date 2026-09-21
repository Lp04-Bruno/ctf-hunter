#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TracepointField {
    pub name: String,
    pub offset: usize,
    pub size: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpectedField<'a> {
    pub name: &'a str,
    pub offset: usize,
    pub size: usize,
}

pub fn verify_tracepoint_format(
    format: &str,
    expected: &[ExpectedField<'_>],
) -> Result<Vec<TracepointField>, String> {
    let fields: Vec<_> = format.lines().filter_map(parse_field).collect();
    for wanted in expected {
        let Some(actual) = fields.iter().find(|field| field.name == wanted.name) else {
            return Err(format!("missing tracepoint field {}", wanted.name));
        };
        if actual.offset != wanted.offset || actual.size != wanted.size {
            return Err(format!(
                "tracepoint field {} has offset {} and size {}, expected offset {} and size {}",
                wanted.name, actual.offset, actual.size, wanted.offset, wanted.size
            ));
        }
    }
    Ok(fields)
}

fn parse_field(line: &str) -> Option<TracepointField> {
    let line = line.trim();
    let declaration = line.strip_prefix("field:")?.split(';').next()?.trim();
    let name = declaration
        .split_whitespace()
        .last()?
        .trim_start_matches('*');
    let offset = numeric_property(line, "offset:")?;
    let size = numeric_property(line, "size:")?;
    Some(TracepointField {
        name: name.to_owned(),
        offset,
        size,
    })
}

fn numeric_property(line: &str, key: &str) -> Option<usize> {
    let value = line
        .split(';')
        .find_map(|part| part.trim().strip_prefix(key))?;
    value.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const WRITE_FORMAT: &str = r#"
field:unsigned short common_type; offset:0; size:2; signed:0;
field:int __syscall_nr; offset:8; size:4; signed:1;
field:unsigned int fd; offset:16; size:8; signed:0;
field:const char * buf; offset:24; size:8; signed:0;
field:size_t count; offset:32; size:8; signed:0;
"#;

    #[test]
    fn accepts_the_expected_x86_64_syscall_layout() {
        let fields = verify_tracepoint_format(
            WRITE_FORMAT,
            &[
                ExpectedField {
                    name: "fd",
                    offset: 16,
                    size: 8,
                },
                ExpectedField {
                    name: "buf",
                    offset: 24,
                    size: 8,
                },
                ExpectedField {
                    name: "count",
                    offset: 32,
                    size: 8,
                },
            ],
        )
        .expect("valid format");

        assert_eq!(fields.len(), 5);
    }

    #[test]
    fn rejects_an_unexpected_layout() {
        let error = verify_tracepoint_format(
            WRITE_FORMAT,
            &[ExpectedField {
                name: "buf",
                offset: 16,
                size: 8,
            }],
        )
        .expect_err("layout must differ");

        assert!(error.contains("expected offset 16"));
    }
}
