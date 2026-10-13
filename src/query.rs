#[derive(Clone, Debug)]
pub struct CallQuery {
    class: String,
    name: String,
    descriptor: Option<String>,
}

#[derive(Clone, Debug)]
pub struct FieldQuery {
    class: String,
    name: String,
    descriptor: Option<String>,
}

pub fn parse_class(value: &str) -> Result<String, String> {
    if !valid_class_name(value)
        || matches!(
            value,
            "void" | "boolean" | "byte" | "char" | "short" | "int" | "long" | "float" | "double"
        )
    {
        return Err(format!("invalid dotted class name: {value}"));
    }

    Ok(format!("L{};", value.replace('.', "/")))
}

pub fn parse_class_prefix(value: &str) -> Result<String, String> {
    let stem = value.strip_suffix('.').unwrap_or(value);
    if !valid_class_name(stem) {
        return Err(format!("invalid dotted class prefix: {value}"));
    }

    Ok(format!("L{}", value.replace('.', "/")))
}

pub fn parse_type(value: &str) -> Result<String, String> {
    let mut base = value;
    let mut dimensions = 0;

    while let Some(element) = base.strip_suffix("[]") {
        base = element;
        dimensions += 1;
    }

    let descriptor = match base {
        "void" if dimensions == 0 => "V".to_owned(),
        "void" => return Err("void cannot be an array element".to_owned()),
        "boolean" => "Z".to_owned(),
        "byte" => "B".to_owned(),
        "char" => "C".to_owned(),
        "short" => "S".to_owned(),
        "int" => "I".to_owned(),
        "long" => "J".to_owned(),
        "float" => "F".to_owned(),
        "double" => "D".to_owned(),
        _ => parse_class(base)?,
    };

    Ok(format!("{}{}", "[".repeat(dimensions), descriptor))
}

pub fn parse_call_query(value: &str) -> Result<CallQuery, String> {
    let (class, member) = split_member(value)?;
    let (name, descriptor) = match member.split_once('(') {
        Some((name, signature)) => {
            let (parameters, return_type) = signature
                .split_once("):")
                .ok_or("method signature must use (parameters):return-type")?;
            let mut descriptor = String::from("(");

            if !parameters.is_empty() {
                for parameter in parameters.split(',') {
                    let ty = parse_type(parameter.trim())?;
                    if ty == "V" {
                        return Err("method parameter cannot be void".to_owned());
                    }

                    descriptor.push_str(&ty);
                }
            }

            descriptor.push(')');
            descriptor.push_str(&parse_type(return_type)?);

            (name, Some(descriptor))
        }
        None => (member, None),
    };

    if !valid_member_name(name) {
        return Err("invalid method name".to_owned());
    }

    Ok(CallQuery {
        class,
        name: name.to_owned(),
        descriptor,
    })
}

pub fn parse_field_query(value: &str) -> Result<FieldQuery, String> {
    let (class, member) = split_member(value)?;
    let (name, descriptor) = match member.split_once(':') {
        Some((name, ty)) => {
            let descriptor = parse_type(ty)?;
            if descriptor == "V" {
                return Err("field type cannot be void".to_owned());
            }

            (name, Some(descriptor))
        }
        None => (member, None),
    };

    if !valid_member_name(name) {
        return Err("invalid field name".to_owned());
    }

    Ok(FieldQuery {
        class,
        name: name.to_owned(),
        descriptor,
    })
}

impl CallQuery {
    pub fn matches(&self, class: &str, name: &str, descriptor: &str) -> bool {
        self.class == class
            && self.name == name
            && self
                .descriptor
                .as_deref()
                .is_none_or(|query| query == descriptor)
    }
}

impl FieldQuery {
    pub fn matches(&self, class: &str, name: &str, descriptor: &str) -> bool {
        self.class == class
            && self.name == name
            && self
                .descriptor
                .as_deref()
                .is_none_or(|query| query == descriptor)
    }
}

fn split_member(value: &str) -> Result<(String, &str), String> {
    let (class, member) = value.split_once('#').ok_or("member must use Class#name")?;

    Ok((parse_class(class)?, member))
}

fn valid_class_name(value: &str) -> bool {
    value.split('.').all(|part| {
        !part.is_empty()
            && part.chars().all(|character| {
                character.is_alphanumeric() || character == '_' || character == '$'
            })
    })
}

fn valid_member_name(value: &str) -> bool {
    !value.is_empty()
        && !value.chars().any(|character| {
            character.is_whitespace() || matches!(character, '#' | ':' | '(' | ')' | ';' | '/')
        })
}

#[cfg(test)]
mod tests {
    use super::{parse_call_query, parse_class, parse_class_prefix, parse_field_query, parse_type};

    #[test]
    fn parses_javadoc_names_and_optional_member_signatures() {
        assert_eq!(
            parse_class("com.example.Outer$Inner").unwrap(),
            "Lcom/example/Outer$Inner;"
        );
        assert_eq!(parse_class_prefix("com.example.").unwrap(), "Lcom/example/");
        assert_eq!(
            parse_type("java.lang.String[][]").unwrap(),
            "[[Ljava/lang/String;"
        );
        assert!(
            parse_call_query("com.example.Client#send")
                .unwrap()
                .matches("Lcom/example/Client;", "send", "(I)V")
        );
        assert!(
            parse_call_query("com.example.Client#send(int):void")
                .unwrap()
                .matches("Lcom/example/Client;", "send", "(I)V")
        );
        assert!(
            !parse_call_query("com.example.Client#send(int):void")
                .unwrap()
                .matches("Lcom/example/Client;", "send", "()V")
        );
        assert!(
            parse_field_query("com.example.Config#key:java.lang.String")
                .unwrap()
                .matches("Lcom/example/Config;", "key", "Ljava/lang/String;")
        );
        assert!(
            parse_field_query("com.example.Config#key")
                .unwrap()
                .matches("Lcom/example/Config;", "key", "I")
        );
        assert!(parse_class("Lcom/example/Client;").is_err());
        assert!(parse_class("int").is_err());
        assert!(parse_type("void[]").is_err());
        assert!(parse_call_query("send").is_err());
        assert!(parse_call_query("com.example.Client#send(int)").is_err());
        assert!(parse_field_query("com.example.Config#key:void").is_err());
    }
}
