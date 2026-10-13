use super::format::ByteView;
use super::opcode::{InstructionDescriptor, Opcode, ReferenceKind};

const CODE_ITEM_HEADER_SIZE: usize = 16;
const INSTRUCTION_COUNT_OFFSET: usize = 12;
const CODE_UNIT_SIZE: usize = 2;

#[derive(Default)]
pub(super) struct CodeReferences {
    pub(super) strings: Vec<(usize, u32)>,
    pub(super) static_fields: Vec<(usize, u32)>,
    pub(super) fields: Vec<(usize, u32)>,
    pub(super) types: Vec<(usize, u32)>,
    pub(super) methods: Vec<(usize, u32)>,
}

pub(super) struct CodeItem<'a> {
    bytes: ByteView<'a>,
    instructions_offset: usize,
    instruction_count: usize,
}

impl<'a> CodeItem<'a> {
    pub(super) fn parse(bytes: &'a [u8], offset: usize) -> Result<Self, String> {
        let bytes = ByteView::new(bytes);
        let instruction_count = bytes.u32(offset + INSTRUCTION_COUNT_OFFSET)? as usize;
        let instructions_offset = offset
            .checked_add(CODE_ITEM_HEADER_SIZE)
            .ok_or("code_item offset overflow")?;

        bytes.slice(
            instructions_offset,
            instruction_count
                .checked_mul(CODE_UNIT_SIZE)
                .ok_or("code_item size overflow")?,
        )?;

        Ok(Self {
            bytes,
            instructions_offset,
            instruction_count,
        })
    }

    fn instructions(&self) -> InstructionReader<'a> {
        InstructionReader {
            bytes: self.bytes,
            instructions_offset: self.instructions_offset,
            instruction_count: self.instruction_count,
            position: 0,
        }
    }

    pub(super) fn references(&self) -> Result<CodeReferences, String> {
        let mut references = CodeReferences::default();
        let mut instructions = self.instructions();

        while let Some(instruction) = instructions.next()? {
            let position = instruction.position as u32;
            match instruction.reference()? {
                Some(InstructionReference::String(index)) => {
                    references.strings.push((index, position));
                }
                Some(InstructionReference::Type(index)) => {
                    references.types.push((index, position));
                }
                Some(InstructionReference::Field { index, is_static }) => {
                    references.fields.push((index, position));
                    if is_static {
                        references.static_fields.push((index, position));
                    }
                }
                Some(InstructionReference::Method(index)) => {
                    references.methods.push((index, position));
                }
                None => {}
            }
        }

        Ok(references)
    }
}

struct InstructionReader<'a> {
    bytes: ByteView<'a>,
    instructions_offset: usize,
    instruction_count: usize,
    position: usize,
}

impl<'a> InstructionReader<'a> {
    fn next(&mut self) -> Result<Option<Instruction<'a>>, String> {
        if self.position == self.instruction_count {
            return Ok(None);
        }

        let instruction = Instruction {
            bytes: self.bytes,
            instructions_offset: self.instructions_offset,
            position: self.position,
        };
        self.position = self
            .position
            .checked_add(instruction.width()?)
            .ok_or("instruction offset overflow")?;

        if self.position > self.instruction_count {
            return Err("DEX instruction extends beyond code_item".to_owned());
        }

        Ok(Some(instruction))
    }
}

struct Instruction<'a> {
    bytes: ByteView<'a>,
    instructions_offset: usize,
    position: usize,
}

impl Instruction<'_> {
    fn code_unit(&self, relative: usize) -> Result<u16, String> {
        let position = self
            .position
            .checked_add(relative)
            .ok_or("instruction operand offset overflow")?;
        let offset = self
            .instructions_offset
            .checked_add(
                position
                    .checked_mul(CODE_UNIT_SIZE)
                    .ok_or("instruction operand offset overflow")?,
            )
            .ok_or("instruction operand offset overflow")?;

        self.bytes.u16(offset)
    }

    fn descriptor(&self) -> Result<InstructionDescriptor, String> {
        InstructionDescriptor::decode(self.code_unit(0)? as u8)
    }

    fn reference(&self) -> Result<Option<InstructionReference>, String> {
        let reference = match self.descriptor()?.reference {
            ReferenceKind::String => InstructionReference::String(self.code_unit(1)? as usize),
            ReferenceKind::JumboString => {
                let low = self.code_unit(1)? as u32;
                let high = self.code_unit(2)? as u32;
                InstructionReference::String(((high << 16) | low) as usize)
            }
            ReferenceKind::Type => InstructionReference::Type(self.code_unit(1)? as usize),
            ReferenceKind::Field => InstructionReference::Field {
                index: self.code_unit(1)? as usize,
                is_static: false,
            },
            ReferenceKind::StaticStringField => InstructionReference::Field {
                index: self.code_unit(1)? as usize,
                is_static: true,
            },
            ReferenceKind::Method => InstructionReference::Method(self.code_unit(1)? as usize),
            ReferenceKind::None => return Ok(None),
        };

        Ok(Some(reference))
    }

    fn width(&self) -> Result<usize, String> {
        let instruction = self.code_unit(0)?;
        let descriptor = self.descriptor()?;

        if !matches!(descriptor.opcode, Opcode::Nop) {
            return Ok(descriptor.format.code_units());
        }

        match instruction >> 8 {
            0 => Ok(descriptor.format.code_units()),
            1 => Ok(4 + self.code_unit(1)? as usize * 2),
            2 => Ok(2 + self.code_unit(1)? as usize * 4),
            3 => {
                let element_width = self.code_unit(1)? as usize;
                let element_count = ((self.code_unit(3)? as u32) << 16) | self.code_unit(2)? as u32;
                Ok(4 + (element_width * element_count as usize).div_ceil(2))
            }
            ident => Err(format!("unknown DEX payload 0x{ident:02x}")),
        }
    }
}

enum InstructionReference {
    String(usize),
    Type(usize),
    Field { index: usize, is_static: bool },
    Method(usize),
}
