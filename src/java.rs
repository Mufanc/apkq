use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

#[derive(Clone, Debug)]
pub struct JavaType {
    name: String,
    descriptor: String,
}

#[derive(Clone, Debug)]
pub struct JavaClass {
    name: String,
    descriptor: String,
}

#[derive(Clone, Debug)]
pub struct JavaField {
    class: JavaClass,
    name: String,
    ty: Option<JavaType>,
}

#[derive(Clone, Debug)]
pub struct JavaMethod {
    class: JavaClass,
    name: String,
    signature: Option<JavaMethodSignature>,
}

#[derive(Clone, Debug)]
pub struct JavaMethodSignature {
    parameters: Vec<JavaType>,
    return_type: JavaType,
    descriptor: String,
}

impl JavaType {
    pub fn from_descriptor(descriptor: &str) -> Result<Self, String> {
        let (ty, rest) = take_type(descriptor, true)?;

        if !rest.is_empty() {
            return Err(format!("invalid type descriptor: {descriptor}"));
        }

        Ok(ty)
    }

    pub(crate) fn map_class(self, names: &HashMap<String, String>) -> Result<Self, String> {
        let base = self.descriptor.trim_start_matches('[');

        if base.starts_with('L') {
            let class = JavaClass::from_descriptor(base)?;

            if let Some(mapped) = names.get(class.name()) {
                let descriptor = format!(
                    "{}{}",
                    &self.descriptor[..self.descriptor.len() - base.len()],
                    mapped.parse::<JavaClass>()?.descriptor()
                );

                return Self::from_descriptor(&descriptor);
            }
        }

        Ok(self)
    }

    pub fn descriptor(&self) -> &str {
        &self.descriptor
    }
}

impl FromStr for JavaType {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
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
            _ => JavaClass::from_str(base)?.descriptor,
        };

        Ok(Self {
            name: value.to_owned(),
            descriptor: format!("{}{descriptor}", "[".repeat(dimensions)),
        })
    }
}

impl fmt::Display for JavaType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.name)
    }
}

impl JavaClass {
    pub fn from_descriptor(descriptor: &str) -> Result<Self, String> {
        let (ty, rest) = take_type(descriptor, false)?;

        if !rest.is_empty() || !descriptor.starts_with('L') {
            return Err(format!("invalid class descriptor: {descriptor}"));
        }

        Ok(Self {
            name: ty.name,
            descriptor: descriptor.to_owned(),
        })
    }

    fn split_member(value: &str) -> Result<(Self, &str), String> {
        let (class, member) = value.split_once('#').ok_or("member must use Class#name")?;

        Ok((class.parse()?, member))
    }

    fn split_descriptor_member(value: &str) -> Result<(Self, &str), String> {
        let (class, member) = value
            .split_once("->")
            .ok_or("descriptor member must use LClass;->name")?;

        Ok((Self::from_descriptor(class)?, member))
    }

    pub fn descriptor(&self) -> &str {
        &self.descriptor
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

impl FromStr for JavaClass {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if !valid_class_name(value) || primitive(value) {
            return Err(format!("invalid dotted class name: {value}"));
        }

        Ok(Self {
            name: value.to_owned(),
            descriptor: format!("L{};", value.replace('.', "/")),
        })
    }
}

impl fmt::Display for JavaClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.name)
    }
}

impl JavaField {
    pub fn from_descriptor(value: &str) -> Result<Self, String> {
        let (class, member) = JavaClass::split_descriptor_member(value)?;
        let (name, ty) = match member.split_once(':') {
            Some((name, descriptor)) => (name, Some(JavaType::from_descriptor(descriptor)?)),
            None => (member, None),
        };

        if !valid_member_name(name) {
            return Err("invalid field name".to_owned());
        }

        if ty.as_ref().is_some_and(|ty| ty.descriptor == "V") {
            return Err("field type cannot be void".to_owned());
        }

        Ok(Self {
            class,
            name: name.to_owned(),
            ty,
        })
    }

    pub fn from_parts(
        class_descriptor: &str,
        name: &str,
        field_descriptor: &str,
    ) -> Result<Self, String> {
        let ty = JavaType::from_descriptor(field_descriptor)?;

        if ty.descriptor == "V" {
            return Err("field type cannot be void".to_owned());
        }

        Ok(Self {
            class: JavaClass::from_descriptor(class_descriptor)?,
            name: name.to_owned(),
            ty: Some(ty),
        })
    }

    pub fn matches(&self, class: &str, name: &str, descriptor: &str) -> bool {
        self.class.descriptor == class
            && self.name == name
            && self
                .ty
                .as_ref()
                .is_none_or(|ty| ty.descriptor == descriptor)
    }
}

impl FromStr for JavaField {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (class, member) = JavaClass::split_member(value)?;
        let (name, ty) = match member.split_once(':') {
            Some((name, ty)) => {
                let ty = JavaType::from_str(ty)?;

                if ty.descriptor == "V" {
                    return Err("field type cannot be void".to_owned());
                }

                (name, Some(ty))
            }
            None => (member, None),
        };

        if !valid_member_name(name) {
            return Err("invalid field name".to_owned());
        }

        Ok(Self {
            class,
            name: name.to_owned(),
            ty,
        })
    }
}

impl fmt::Display for JavaField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}#{}", self.class, self.name)?;

        if let Some(ty) = &self.ty {
            write!(formatter, ":{ty}")?;
        }

        Ok(())
    }
}

impl JavaMethod {
    pub fn class(&self) -> &JavaClass {
        &self.class
    }

    pub fn from_descriptor(value: &str) -> Result<Self, String> {
        let (class, member) = JavaClass::split_descriptor_member(value)?;
        let (name, signature) = match member.find('(') {
            Some(open) => (
                &member[..open],
                Some(JavaMethodSignature::from_descriptor(&member[open..])?),
            ),
            None => (member, None),
        };

        if !valid_member_name(name) {
            return Err("invalid method name".to_owned());
        }

        Ok(Self {
            class,
            name: name.to_owned(),
            signature,
        })
    }

    pub fn from_parts(
        class_descriptor: &str,
        name: &str,
        method_descriptor: &str,
    ) -> Result<Self, String> {
        Ok(Self {
            class: JavaClass::from_descriptor(class_descriptor)?,
            name: name.to_owned(),
            signature: Some(JavaMethodSignature::from_descriptor(method_descriptor)?),
        })
    }

    pub fn matches(&self, class: &str, name: &str, descriptor: &str) -> bool {
        self.class.descriptor == class
            && self.name == name
            && self
                .signature
                .as_ref()
                .is_none_or(|signature| signature.descriptor == descriptor)
    }
}

impl FromStr for JavaMethod {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (class, member) = JavaClass::split_member(value)?;
        let (name, signature) = match member.find('(') {
            Some(open) => (
                &member[..open],
                Some(member[open..].parse::<JavaMethodSignature>()?),
            ),
            None => (member, None),
        };

        if !valid_member_name(name) {
            return Err("invalid method name".to_owned());
        }

        Ok(Self {
            class,
            name: name.to_owned(),
            signature,
        })
    }
}

impl fmt::Display for JavaMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}#{}", self.class, self.name)?;

        if let Some(signature) = &self.signature {
            write!(formatter, "{signature}")?;
        }

        Ok(())
    }
}

impl FromStr for JavaMethodSignature {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (parameters, return_type) = value
            .strip_prefix('(')
            .and_then(|value| value.split_once("):"))
            .ok_or("method signature must use (parameters):return-type")?;
        let parameters = if parameters.is_empty() {
            Vec::new()
        } else {
            parameters
                .split(',')
                .map(|parameter| {
                    let ty = JavaType::from_str(parameter.trim())?;

                    if ty.descriptor == "V" {
                        return Err("method parameter cannot be void".to_owned());
                    }

                    Ok(ty)
                })
                .collect::<Result<Vec<_>, _>>()?
        };

        let return_type = JavaType::from_str(return_type)?;
        let descriptor = format!(
            "({}){}",
            parameters
                .iter()
                .map(JavaType::descriptor)
                .collect::<String>(),
            return_type.descriptor
        );

        Ok(Self {
            parameters,
            return_type,
            descriptor,
        })
    }
}

impl JavaMethodSignature {
    pub fn from_descriptor(descriptor: &str) -> Result<Self, String> {
        let (parameters, return_type) = descriptor
            .strip_prefix('(')
            .and_then(|value| value.split_once(')'))
            .ok_or_else(|| format!("invalid method descriptor: {descriptor}"))?;
        let mut remaining = parameters;
        let mut parsed = Vec::new();

        while !remaining.is_empty() {
            let (parameter, rest) = take_type(remaining, false)?;

            parsed.push(parameter);
            remaining = rest;
        }

        let return_type = JavaType::from_descriptor(return_type)?;

        Ok(Self {
            parameters: parsed,
            return_type,
            descriptor: descriptor.to_owned(),
        })
    }
}

impl fmt::Display for JavaMethodSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "(")?;

        for (index, parameter) in self.parameters.iter().enumerate() {
            if index > 0 {
                formatter.write_str(",")?;
            }

            write!(formatter, "{parameter}")?;
        }

        write!(formatter, "):{}", self.return_type)
    }
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
        && !value.contains("->")
        && !value.chars().any(|character| {
            character.is_whitespace() || matches!(character, '#' | ':' | '(' | ')' | ';' | '/')
        })
}

fn primitive(value: &str) -> bool {
    matches!(
        value,
        "void" | "boolean" | "byte" | "char" | "short" | "int" | "long" | "float" | "double"
    )
}

fn take_type(descriptor: &str, allow_void: bool) -> Result<(JavaType, &str), String> {
    let mut value = descriptor;
    let mut dimensions = 0;

    while let Some(element) = value.strip_prefix('[') {
        value = element;
        dimensions += 1;
    }

    let (name, rest) = match value.as_bytes().first() {
        Some(b'V') if allow_void && dimensions == 0 => ("void".to_owned(), &value[1..]),
        Some(b'Z') => ("boolean".to_owned(), &value[1..]),
        Some(b'B') => ("byte".to_owned(), &value[1..]),
        Some(b'C') => ("char".to_owned(), &value[1..]),
        Some(b'S') => ("short".to_owned(), &value[1..]),
        Some(b'I') => ("int".to_owned(), &value[1..]),
        Some(b'J') => ("long".to_owned(), &value[1..]),
        Some(b'F') => ("float".to_owned(), &value[1..]),
        Some(b'D') => ("double".to_owned(), &value[1..]),
        Some(b'L') => {
            let end = value
                .find(';')
                .ok_or_else(|| format!("invalid type descriptor: {descriptor}"))?;
            let class = &value[1..end];

            if class.split('/').any(|part| {
                part.is_empty()
                    || part.chars().any(|character| {
                        character.is_whitespace()
                            || matches!(character, '.' | '[' | ':' | '(' | ')' | '#')
                    })
            }) {
                return Err(format!("invalid type descriptor: {descriptor}"));
            }

            (class.replace('/', "."), &value[end + 1..])
        }
        _ => return Err(format!("invalid type descriptor: {descriptor}")),
    };

    let consumed = descriptor.len() - rest.len();

    Ok((
        JavaType {
            name: format!("{name}{}", "[]".repeat(dimensions)),
            descriptor: descriptor[..consumed].to_owned(),
        },
        rest,
    ))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::{JavaClass, JavaField, JavaMethod, JavaType};

    #[test]
    fn parses_smali_symbols_into_the_same_java_symbols() {
        for (java, smali, descriptor) in [
            (
                "com.example.Client#send(int,java.lang.String[]):boolean",
                "Lcom/example/Client;->send(I[Ljava/lang/String;)Z",
                "(I[Ljava/lang/String;)Z",
            ),
            (
                "com.example.Client#<init>():void",
                "Lcom/example/Client;-><init>()V",
                "()V",
            ),
        ] {
            let java: JavaMethod = java.parse().unwrap();
            let smali = JavaMethod::from_descriptor(smali).unwrap();
            assert_eq!(java.to_string(), smali.to_string());
            assert!(smali.matches(java.class().descriptor(), &java.name, descriptor));
        }
        let method = JavaMethod::from_descriptor("Lcom/example/Client;->send").unwrap();
        assert!(method.matches("Lcom/example/Client;", "send", "(I)V"));
        assert!(method.matches("Lcom/example/Client;", "send", "()V"));
        let field = JavaField::from_descriptor("Lcom/example/Client;->values:[I").unwrap();
        assert_eq!(field.to_string(), "com.example.Client#values:int[]");
        assert!(field.matches("Lcom/example/Client;", "values", "[I"));
        assert!(
            JavaField::from_descriptor("Lcom/example/Client;->values")
                .unwrap()
                .matches("Lcom/example/Client;", "values", "[I")
        );
        assert_eq!(
            JavaType::from_descriptor("[[Ljava/lang/String;")
                .unwrap()
                .to_string(),
            "java.lang.String[][]"
        );
        assert_eq!(JavaType::from_descriptor("I").unwrap().to_string(), "int");
        assert_eq!("I".parse::<JavaType>().unwrap().descriptor(), "LI;");
    }

    #[test]
    fn rejects_malformed_smali_symbols() {
        for value in [
            "Lcom/example/Client;->send(I)",
            "Lcom/example/Client;->send(V)V",
            "Lcom/example/Client;->send()Vextra",
            "Lcom/example/Client;->send([V)V",
            "com.example.Client->send()V",
            "Lcom/example/Client;->send(int):void",
        ] {
            assert!(JavaMethod::from_descriptor(value).is_err(), "{value}");
        }
        for value in [
            "Lcom/example/Client;->values:V",
            "Lcom/example/Client;->values:[",
            "Lcom/example/Client;->values:Ljava/lang/String;;",
            "Lcom/example/Client;->values:",
        ] {
            assert!(JavaField::from_descriptor(value).is_err(), "{value}");
        }
    }

    #[test]
    fn parses_and_formats_java_symbols() {
        let class = JavaClass::from_str("com.example.Outer$Inner").unwrap();
        assert_eq!(class.descriptor(), "Lcom/example/Outer$Inner;");
        assert_eq!(class.to_string(), "com.example.Outer$Inner");

        let ty = JavaType::from_str("java.lang.String[][]").unwrap();
        assert_eq!(ty.descriptor(), "[[Ljava/lang/String;");

        let method = JavaMethod::from_str("com.example.Client#send(int):void").unwrap();
        assert!(method.matches("Lcom/example/Client;", "send", "(I)V"));
        assert!(!method.matches("Lcom/example/Client;", "send", "()V"));

        let field = JavaField::from_str("com.example.Config#key:java.lang.String").unwrap();
        assert!(field.matches("Lcom/example/Config;", "key", "Ljava/lang/String;"));

        assert_eq!(
            JavaClass::from_descriptor("Lcom/example/Client;")
                .unwrap()
                .to_string(),
            "com.example.Client"
        );
        assert!(JavaType::from_str("void[]").is_err());
        assert!(JavaMethod::from_str("send").is_err());
        assert!(JavaMethod::from_str("com.example.Client#send(int)").is_err());
        assert!(JavaField::from_str("com.example.Config#key:void").is_err());
    }

    #[test]
    fn preserves_single_letter_classes_in_nested_java_types() {
        for name in ["V", "Z", "B", "C", "S", "I", "J", "F", "D"] {
            let descriptor = format!("L{name};");
            for ty in [descriptor.clone(), format!("[{descriptor}")] {
                let field = JavaField::from_parts("LOwner;", "value", &ty).unwrap();
                let parsed: JavaField = field.to_string().parse().unwrap();
                assert!(parsed.matches("LOwner;", "value", &ty));
                let signature = format!("({ty}){ty}");
                let method = JavaMethod::from_parts("LOwner;", "call", &signature).unwrap();
                let parsed: JavaMethod = method.to_string().parse().unwrap();
                assert!(parsed.matches("LOwner;", "call", &signature));
            }
        }
    }

    #[test]
    fn keeps_java_and_descriptor_parsing_explicit() {
        assert!("LOwner;".parse::<JavaClass>().is_err());
        assert!("[I".parse::<JavaType>().is_err());
        assert!("LOwner;->call(I)V".parse::<JavaMethod>().is_err());
        assert!("LOwner;->value:I".parse::<JavaField>().is_err());
        assert!(JavaClass::from_descriptor("Owner").is_err());
        assert!(JavaType::from_descriptor("int").is_err());
        assert!(JavaMethod::from_descriptor("Owner#call(int):void").is_err());
        assert!(JavaField::from_descriptor("Owner#value:int").is_err());
    }

    #[test]
    fn converts_dex_descriptors_to_java_symbols() {
        assert_eq!(
            JavaField::from_parts("Lcom/example/Config;", "key", "[Ljava/lang/String;")
                .unwrap()
                .to_string(),
            "com.example.Config#key:java.lang.String[]"
        );
        assert_eq!(
            JavaMethod::from_parts("Lcom/example/Client;", "send", "(I[Ljava/lang/String;)Z",)
                .unwrap()
                .to_string(),
            "com.example.Client#send(int,java.lang.String[]):boolean"
        );
        assert!(JavaMethod::from_parts("Lcom/example/Client;", "send", "(I)Vjunk").is_err());
    }
}
