macro_rules! define_opcodes {
    ($($name:ident = $value:literal, $format:ident, $reference:ident;)+) => {
        #[derive(Clone, Copy)]
        #[repr(u8)]
        pub(super) enum Opcode {
            $($name = $value,)+
        }

        impl Opcode {
            fn decode(value: u8) -> Option<Self> {
                match value {
                    $($value => Some(Self::$name),)+
                    _ => None,
                }
            }

            fn descriptor(self) -> InstructionDescriptor {
                match self {
                    $(Self::$name => InstructionDescriptor {
                        opcode: self,
                        format: InstructionFormat::$format,
                        reference: ReferenceKind::$reference,
                    },)+
                }
            }
        }
    };
}

define_opcodes! {
    Nop = 0x00, Format10x, None;
    Move = 0x01, Format12x, None;
    MoveFrom16 = 0x02, Format22x, None;
    Move16 = 0x03, Format32x, None;
    MoveWide = 0x04, Format12x, None;
    MoveWideFrom16 = 0x05, Format22x, None;
    MoveWide16 = 0x06, Format32x, None;
    MoveObject = 0x07, Format12x, None;
    MoveObjectFrom16 = 0x08, Format22x, None;
    MoveObject16 = 0x09, Format32x, None;
    MoveResult = 0x0a, Format11x, None;
    MoveResultWide = 0x0b, Format11x, None;
    MoveResultObject = 0x0c, Format11x, None;
    MoveException = 0x0d, Format11x, None;
    ReturnVoid = 0x0e, Format10x, None;
    Return = 0x0f, Format11x, None;
    ReturnWide = 0x10, Format11x, None;
    ReturnObject = 0x11, Format11x, None;
    Const4 = 0x12, Format11n, None;
    Const16 = 0x13, Format21s, None;
    Const = 0x14, Format31i, None;
    ConstHigh16 = 0x15, Format21h, None;
    ConstWide16 = 0x16, Format21s, None;
    ConstWide32 = 0x17, Format31i, None;
    ConstWide = 0x18, Format51l, None;
    ConstWideHigh16 = 0x19, Format21h, None;
    ConstString = 0x1a, Format21c, String;
    ConstStringJumbo = 0x1b, Format31c, JumboString;
    ConstClass = 0x1c, Format21c, Type;
    MonitorEnter = 0x1d, Format11x, None;
    MonitorExit = 0x1e, Format11x, None;
    CheckCast = 0x1f, Format21c, Type;
    InstanceOf = 0x20, Format22c, Type;
    ArrayLength = 0x21, Format12x, None;
    NewInstance = 0x22, Format21c, Type;
    NewArray = 0x23, Format22c, Type;
    FilledNewArray = 0x24, Format35c, Type;
    FilledNewArrayRange = 0x25, Format3rc, Type;
    FillArrayData = 0x26, Format31t, None;
    Throw = 0x27, Format11x, None;
    Goto = 0x28, Format10t, None;
    Goto16 = 0x29, Format20t, None;
    Goto32 = 0x2a, Format30t, None;
    PackedSwitch = 0x2b, Format31t, None;
    SparseSwitch = 0x2c, Format31t, None;
    CmplFloat = 0x2d, Format23x, None;
    CmpgFloat = 0x2e, Format23x, None;
    CmplDouble = 0x2f, Format23x, None;
    CmpgDouble = 0x30, Format23x, None;
    CmpLong = 0x31, Format23x, None;
    IfEq = 0x32, Format22t, None;
    IfNe = 0x33, Format22t, None;
    IfLt = 0x34, Format22t, None;
    IfGe = 0x35, Format22t, None;
    IfGt = 0x36, Format22t, None;
    IfLe = 0x37, Format22t, None;
    IfEqz = 0x38, Format21t, None;
    IfNez = 0x39, Format21t, None;
    IfLtz = 0x3a, Format21t, None;
    IfGez = 0x3b, Format21t, None;
    IfGtz = 0x3c, Format21t, None;
    IfLez = 0x3d, Format21t, None;
    Aget = 0x44, Format23x, None;
    AgetWide = 0x45, Format23x, None;
    AgetObject = 0x46, Format23x, None;
    AgetBoolean = 0x47, Format23x, None;
    AgetByte = 0x48, Format23x, None;
    AgetChar = 0x49, Format23x, None;
    AgetShort = 0x4a, Format23x, None;
    Aput = 0x4b, Format23x, None;
    AputWide = 0x4c, Format23x, None;
    AputObject = 0x4d, Format23x, None;
    AputBoolean = 0x4e, Format23x, None;
    AputByte = 0x4f, Format23x, None;
    AputChar = 0x50, Format23x, None;
    AputShort = 0x51, Format23x, None;
    Iget = 0x52, Format22c, Field;
    IgetWide = 0x53, Format22c, Field;
    IgetObject = 0x54, Format22c, Field;
    IgetBoolean = 0x55, Format22c, Field;
    IgetByte = 0x56, Format22c, Field;
    IgetChar = 0x57, Format22c, Field;
    IgetShort = 0x58, Format22c, Field;
    Iput = 0x59, Format22c, Field;
    IputWide = 0x5a, Format22c, Field;
    IputObject = 0x5b, Format22c, Field;
    IputBoolean = 0x5c, Format22c, Field;
    IputByte = 0x5d, Format22c, Field;
    IputChar = 0x5e, Format22c, Field;
    IputShort = 0x5f, Format22c, Field;
    Sget = 0x60, Format21c, Field;
    SgetWide = 0x61, Format21c, Field;
    SgetObject = 0x62, Format21c, StaticStringField;
    SgetBoolean = 0x63, Format21c, Field;
    SgetByte = 0x64, Format21c, Field;
    SgetChar = 0x65, Format21c, Field;
    SgetShort = 0x66, Format21c, Field;
    Sput = 0x67, Format21c, Field;
    SputWide = 0x68, Format21c, Field;
    SputObject = 0x69, Format21c, Field;
    SputBoolean = 0x6a, Format21c, Field;
    SputByte = 0x6b, Format21c, Field;
    SputChar = 0x6c, Format21c, Field;
    SputShort = 0x6d, Format21c, Field;
    InvokeVirtual = 0x6e, Format35c, Method;
    InvokeSuper = 0x6f, Format35c, Method;
    InvokeDirect = 0x70, Format35c, Method;
    InvokeStatic = 0x71, Format35c, Method;
    InvokeInterface = 0x72, Format35c, Method;
    InvokeVirtualRange = 0x74, Format3rc, Method;
    InvokeSuperRange = 0x75, Format3rc, Method;
    InvokeDirectRange = 0x76, Format3rc, Method;
    InvokeStaticRange = 0x77, Format3rc, Method;
    InvokeInterfaceRange = 0x78, Format3rc, Method;
    NegInt = 0x7b, Format12x, None;
    NotInt = 0x7c, Format12x, None;
    NegLong = 0x7d, Format12x, None;
    NotLong = 0x7e, Format12x, None;
    NegFloat = 0x7f, Format12x, None;
    NegDouble = 0x80, Format12x, None;
    IntToLong = 0x81, Format12x, None;
    IntToFloat = 0x82, Format12x, None;
    IntToDouble = 0x83, Format12x, None;
    LongToInt = 0x84, Format12x, None;
    LongToFloat = 0x85, Format12x, None;
    LongToDouble = 0x86, Format12x, None;
    FloatToInt = 0x87, Format12x, None;
    FloatToLong = 0x88, Format12x, None;
    FloatToDouble = 0x89, Format12x, None;
    DoubleToInt = 0x8a, Format12x, None;
    DoubleToLong = 0x8b, Format12x, None;
    DoubleToFloat = 0x8c, Format12x, None;
    IntToByte = 0x8d, Format12x, None;
    IntToChar = 0x8e, Format12x, None;
    IntToShort = 0x8f, Format12x, None;
    AddInt = 0x90, Format23x, None;
    SubInt = 0x91, Format23x, None;
    MulInt = 0x92, Format23x, None;
    DivInt = 0x93, Format23x, None;
    RemInt = 0x94, Format23x, None;
    AndInt = 0x95, Format23x, None;
    OrInt = 0x96, Format23x, None;
    XorInt = 0x97, Format23x, None;
    ShlInt = 0x98, Format23x, None;
    ShrInt = 0x99, Format23x, None;
    UshrInt = 0x9a, Format23x, None;
    AddLong = 0x9b, Format23x, None;
    SubLong = 0x9c, Format23x, None;
    MulLong = 0x9d, Format23x, None;
    DivLong = 0x9e, Format23x, None;
    RemLong = 0x9f, Format23x, None;
    AndLong = 0xa0, Format23x, None;
    OrLong = 0xa1, Format23x, None;
    XorLong = 0xa2, Format23x, None;
    ShlLong = 0xa3, Format23x, None;
    ShrLong = 0xa4, Format23x, None;
    UshrLong = 0xa5, Format23x, None;
    AddFloat = 0xa6, Format23x, None;
    SubFloat = 0xa7, Format23x, None;
    MulFloat = 0xa8, Format23x, None;
    DivFloat = 0xa9, Format23x, None;
    RemFloat = 0xaa, Format23x, None;
    AddDouble = 0xab, Format23x, None;
    SubDouble = 0xac, Format23x, None;
    MulDouble = 0xad, Format23x, None;
    DivDouble = 0xae, Format23x, None;
    RemDouble = 0xaf, Format23x, None;
    AddInt2Addr = 0xb0, Format12x, None;
    SubInt2Addr = 0xb1, Format12x, None;
    MulInt2Addr = 0xb2, Format12x, None;
    DivInt2Addr = 0xb3, Format12x, None;
    RemInt2Addr = 0xb4, Format12x, None;
    AndInt2Addr = 0xb5, Format12x, None;
    OrInt2Addr = 0xb6, Format12x, None;
    XorInt2Addr = 0xb7, Format12x, None;
    ShlInt2Addr = 0xb8, Format12x, None;
    ShrInt2Addr = 0xb9, Format12x, None;
    UshrInt2Addr = 0xba, Format12x, None;
    AddLong2Addr = 0xbb, Format12x, None;
    SubLong2Addr = 0xbc, Format12x, None;
    MulLong2Addr = 0xbd, Format12x, None;
    DivLong2Addr = 0xbe, Format12x, None;
    RemLong2Addr = 0xbf, Format12x, None;
    AndLong2Addr = 0xc0, Format12x, None;
    OrLong2Addr = 0xc1, Format12x, None;
    XorLong2Addr = 0xc2, Format12x, None;
    ShlLong2Addr = 0xc3, Format12x, None;
    ShrLong2Addr = 0xc4, Format12x, None;
    UshrLong2Addr = 0xc5, Format12x, None;
    AddFloat2Addr = 0xc6, Format12x, None;
    SubFloat2Addr = 0xc7, Format12x, None;
    MulFloat2Addr = 0xc8, Format12x, None;
    DivFloat2Addr = 0xc9, Format12x, None;
    RemFloat2Addr = 0xca, Format12x, None;
    AddDouble2Addr = 0xcb, Format12x, None;
    SubDouble2Addr = 0xcc, Format12x, None;
    MulDouble2Addr = 0xcd, Format12x, None;
    DivDouble2Addr = 0xce, Format12x, None;
    RemDouble2Addr = 0xcf, Format12x, None;
    AddIntLit16 = 0xd0, Format22s, None;
    RsubInt = 0xd1, Format22s, None;
    MulIntLit16 = 0xd2, Format22s, None;
    DivIntLit16 = 0xd3, Format22s, None;
    RemIntLit16 = 0xd4, Format22s, None;
    AndIntLit16 = 0xd5, Format22s, None;
    OrIntLit16 = 0xd6, Format22s, None;
    XorIntLit16 = 0xd7, Format22s, None;
    AddIntLit8 = 0xd8, Format22b, None;
    RsubIntLit8 = 0xd9, Format22b, None;
    MulIntLit8 = 0xda, Format22b, None;
    DivIntLit8 = 0xdb, Format22b, None;
    RemIntLit8 = 0xdc, Format22b, None;
    AndIntLit8 = 0xdd, Format22b, None;
    OrIntLit8 = 0xde, Format22b, None;
    XorIntLit8 = 0xdf, Format22b, None;
    ShlIntLit8 = 0xe0, Format22b, None;
    ShrIntLit8 = 0xe1, Format22b, None;
    UshrIntLit8 = 0xe2, Format22b, None;
    InvokePolymorphic = 0xfa, Format45cc, Method;
    InvokePolymorphicRange = 0xfb, Format4rcc, Method;
    InvokeCustom = 0xfc, Format35c, None;
    InvokeCustomRange = 0xfd, Format3rc, None;
    ConstMethodHandle = 0xfe, Format21c, None;
    ConstMethodType = 0xff, Format21c, None;
}

#[derive(Clone, Copy)]
pub(super) struct InstructionDescriptor {
    pub(super) opcode: Opcode,
    pub(super) format: InstructionFormat,
    pub(super) reference: ReferenceKind,
}

#[derive(Clone, Copy)]
pub(super) enum InstructionFormat {
    Format10t,
    Format10x,
    Format11n,
    Format11x,
    Format12x,
    Format20t,
    Format21c,
    Format21h,
    Format21s,
    Format21t,
    Format22b,
    Format22c,
    Format22s,
    Format22t,
    Format22x,
    Format23x,
    Format30t,
    Format31c,
    Format31i,
    Format31t,
    Format32x,
    Format35c,
    Format3rc,
    Format45cc,
    Format4rcc,
    Format51l,
}

#[derive(Clone, Copy)]
pub(super) enum ReferenceKind {
    None,
    String,
    JumboString,
    Type,
    Field,
    StaticStringField,
    Method,
}

impl InstructionDescriptor {
    pub(super) fn decode(value: u8) -> Result<Self, String> {
        Opcode::decode(value)
            .map(Opcode::descriptor)
            .ok_or_else(|| format!("unknown DEX opcode 0x{value:02x}"))
    }
}

impl InstructionFormat {
    pub(super) fn code_units(self) -> usize {
        match self {
            Self::Format10t
            | Self::Format10x
            | Self::Format11n
            | Self::Format11x
            | Self::Format12x => 1,
            Self::Format20t
            | Self::Format21c
            | Self::Format21h
            | Self::Format21s
            | Self::Format21t
            | Self::Format22b
            | Self::Format22c
            | Self::Format22s
            | Self::Format22t
            | Self::Format22x
            | Self::Format23x => 2,
            Self::Format30t
            | Self::Format31c
            | Self::Format31i
            | Self::Format31t
            | Self::Format32x
            | Self::Format35c
            | Self::Format3rc => 3,
            Self::Format45cc | Self::Format4rcc => 4,
            Self::Format51l => 5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{InstructionDescriptor, InstructionFormat, Opcode, ReferenceKind};

    #[test]
    fn decodes_formats_and_reference_kinds_together() {
        let string = InstructionDescriptor::decode(0x1a).unwrap();
        assert!(matches!(string.opcode, Opcode::ConstString));
        assert!(matches!(string.format, InstructionFormat::Format21c));
        assert!(matches!(string.reference, ReferenceKind::String));

        let static_string = InstructionDescriptor::decode(0x62).unwrap();
        assert!(matches!(static_string.opcode, Opcode::SgetObject));
        assert!(matches!(static_string.format, InstructionFormat::Format21c));
        assert!(matches!(
            static_string.reference,
            ReferenceKind::StaticStringField
        ));

        let polymorphic = InstructionDescriptor::decode(0xfa).unwrap();
        assert!(matches!(polymorphic.format, InstructionFormat::Format45cc));
        assert!(matches!(polymorphic.reference, ReferenceKind::Method));

        assert!(InstructionDescriptor::decode(0x3e).is_err());
        assert!(InstructionDescriptor::decode(0xe3).is_err());
    }
}
