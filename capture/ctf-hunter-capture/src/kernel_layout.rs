use std::{fs, path::Path};

const BTF_MAGIC: u16 = 0xeb9f;
const KIND_INT: u32 = 1;
const KIND_PTR: u32 = 2;
const KIND_ARRAY: u32 = 3;
const KIND_STRUCT: u32 = 4;
const KIND_FUNC: u32 = 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelLayout {
    pub task_signal: u32,
    pub signal_pgid: u32,
    pub tty_pgrp: u32,
    pub tty_device: u32,
    pub device_devt: u32,
}

impl KernelLayout {
    pub fn from_path(path: &Path) -> Result<Self, String> {
        let bytes = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
        Self::from_bytes(&bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let btf = ParsedBtf::parse(bytes)?;
        btf.require_function("n_tty_read")?;
        btf.require_function("n_tty_write")?;

        let task = btf.named_struct("task_struct")?;
        let (task_signal, signal_pointer) = btf.member(task, "signal")?;
        let signal = btf.pointed_struct(signal_pointer, "signal_struct")?;
        let (signal_pids, pids_array) = btf.member(signal, "pids")?;
        let pids = btf.array(pids_array)?;
        if pids.count <= 2 || !btf.is_pointer(pids.element_type)? {
            return Err("signal_struct.pids has an unsupported BTF shape".to_owned());
        }

        let tty = btf.named_struct("tty_struct")?;
        let (tty_device, device_pointer) = btf.member(tty, "dev")?;
        let device = btf.pointed_struct(device_pointer, "device")?;
        let (device_devt, devt_type) = btf.member(device, "devt")?;
        if btf.type_size(devt_type)? != 4 {
            return Err("device.devt is not a 32-bit dev_t".to_owned());
        }
        let (tty_ctrl, ctrl_type) = btf.member(tty, "ctrl")?;
        let (ctrl_pgrp, pgrp_type) = btf.member(btf.resolve(ctrl_type)?, "pgrp")?;
        if !btf.is_pointer(pgrp_type)? {
            return Err("tty_struct.ctrl.pgrp is not a pointer".to_owned());
        }

        let pointer_size = u32::try_from(std::mem::size_of::<usize>())
            .map_err(|_| "pointer size does not fit u32")?;
        Ok(Self {
            task_signal,
            signal_pgid: signal_pids + (2 * pointer_size),
            tty_pgrp: tty_ctrl + ctrl_pgrp,
            tty_device,
            device_devt,
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct Member {
    name_offset: u32,
    type_id: u32,
    bit_offset: u32,
}

#[derive(Clone, Copy, Debug)]
struct Array {
    element_type: u32,
    count: u32,
}

#[derive(Clone, Debug)]
struct Type {
    name_offset: u32,
    kind: u32,
    size_or_type: u32,
    members: Vec<Member>,
    array: Option<Array>,
}

#[derive(Debug)]
struct ParsedBtf<'a> {
    strings: &'a [u8],
    types: Vec<Type>,
}

impl<'a> ParsedBtf<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, String> {
        if bytes.len() < 24 || read_u16(bytes, 0)? != BTF_MAGIC {
            return Err("invalid BTF header".to_owned());
        }
        if bytes[2] != 1 {
            return Err(format!("unsupported BTF version {}", bytes[2]));
        }
        let header_len = usize_from_u32(read_u32(bytes, 4)?)?;
        let type_offset = usize_from_u32(read_u32(bytes, 8)?)?;
        let type_len = usize_from_u32(read_u32(bytes, 12)?)?;
        let string_offset = usize_from_u32(read_u32(bytes, 16)?)?;
        let string_len = usize_from_u32(read_u32(bytes, 20)?)?;
        let type_start = checked_add(header_len, type_offset)?;
        let type_end = checked_add(type_start, type_len)?;
        let string_start = checked_add(header_len, string_offset)?;
        let string_end = checked_add(string_start, string_len)?;
        if type_end > bytes.len() || string_end > bytes.len() || type_end > string_start {
            return Err("BTF sections are out of bounds".to_owned());
        }
        let strings = &bytes[string_start..string_end];
        let mut cursor = type_start;
        let mut types = vec![Type {
            name_offset: 0,
            kind: 0,
            size_or_type: 0,
            members: Vec::new(),
            array: None,
        }];
        while cursor < type_end {
            if checked_add(cursor, 12)? > type_end {
                return Err("truncated BTF type".to_owned());
            }
            let name_offset = read_u32(bytes, cursor)?;
            let info = read_u32(bytes, cursor + 4)?;
            let size_or_type = read_u32(bytes, cursor + 8)?;
            let kind = (info >> 24) & 0x1f;
            let vlen = usize_from_u32(info & 0xffff)?;
            let kind_flag = info >> 31;
            cursor += 12;

            let mut members = Vec::new();
            let mut array = None;
            let extra_len = match kind {
                KIND_INT => 4,
                KIND_PTR | 7..=12 | 16 | 18 => 0,
                KIND_ARRAY => {
                    array = Some(Array {
                        element_type: read_u32(bytes, cursor)?,
                        count: read_u32(bytes, cursor + 8)?,
                    });
                    12
                }
                KIND_STRUCT | 5 => {
                    for index in 0..vlen {
                        let base = checked_add(cursor, index * 12)?;
                        let encoded_offset = read_u32(bytes, base + 8)?;
                        let bit_offset = if kind_flag == 0 {
                            encoded_offset
                        } else {
                            encoded_offset & 0x00ff_ffff
                        };
                        members.push(Member {
                            name_offset: read_u32(bytes, base)?,
                            type_id: read_u32(bytes, base + 4)?,
                            bit_offset,
                        });
                    }
                    vlen * 12
                }
                6 => vlen * 8,
                13 => vlen * 8,
                14 | 17 => 4,
                15 | 19 => vlen * 12,
                _ => return Err(format!("unsupported BTF kind {kind}")),
            };
            cursor = checked_add(cursor, extra_len)?;
            if cursor > type_end {
                return Err("truncated BTF type data".to_owned());
            }
            types.push(Type {
                name_offset,
                kind,
                size_or_type,
                members,
                array,
            });
        }
        Ok(Self { strings, types })
    }

    fn named_struct(&self, name: &str) -> Result<u32, String> {
        self.types
            .iter()
            .enumerate()
            .find(|(_, value)| {
                value.kind == KIND_STRUCT && self.name(value.name_offset) == Ok(name)
            })
            .map(|(index, _)| index as u32)
            .ok_or_else(|| format!("kernel BTF is missing struct {name}"))
    }

    fn require_function(&self, name: &str) -> Result<(), String> {
        if self
            .types
            .iter()
            .any(|value| value.kind == KIND_FUNC && self.name(value.name_offset) == Ok(name))
        {
            Ok(())
        } else {
            Err(format!("kernel BTF is missing function {name}"))
        }
    }

    fn member(&self, struct_id: u32, name: &str) -> Result<(u32, u32), String> {
        let value = self.ty(struct_id)?;
        if value.kind != KIND_STRUCT {
            return Err(format!("BTF type {struct_id} is not a struct"));
        }
        let member = value
            .members
            .iter()
            .find(|member| self.name(member.name_offset) == Ok(name))
            .ok_or_else(|| format!("BTF struct is missing member {name}"))?;
        if member.bit_offset % 8 != 0 {
            return Err(format!("BTF member {name} is not byte-aligned"));
        }
        Ok((member.bit_offset / 8, member.type_id))
    }

    fn pointed_struct(&self, pointer: u32, expected: &str) -> Result<u32, String> {
        let pointer = self.ty(self.resolve(pointer)?)?;
        if pointer.kind != KIND_PTR {
            return Err(format!("{expected} reference is not a pointer"));
        }
        let target = self.resolve(pointer.size_or_type)?;
        let value = self.ty(target)?;
        if value.kind != KIND_STRUCT || self.name(value.name_offset)? != expected {
            return Err(format!("pointer does not reference struct {expected}"));
        }
        Ok(target)
    }

    fn array(&self, type_id: u32) -> Result<Array, String> {
        self.ty(self.resolve(type_id)?)?
            .array
            .ok_or_else(|| "BTF type is not an array".to_owned())
    }

    fn is_pointer(&self, type_id: u32) -> Result<bool, String> {
        Ok(self.ty(self.resolve(type_id)?)?.kind == KIND_PTR)
    }

    fn type_size(&self, type_id: u32) -> Result<u32, String> {
        let value = self.ty(self.resolve(type_id)?)?;
        match value.kind {
            KIND_INT | KIND_STRUCT | 5 | 6 | 16 | 19 => Ok(value.size_or_type),
            KIND_PTR => Ok(std::mem::size_of::<usize>() as u32),
            _ => Err("BTF type has no supported size".to_owned()),
        }
    }

    fn resolve(&self, mut type_id: u32) -> Result<u32, String> {
        for _ in 0..16 {
            let value = self.ty(type_id)?;
            if matches!(value.kind, 8..=11 | 18) {
                type_id = value.size_or_type;
            } else {
                return Ok(type_id);
            }
        }
        Err("BTF type alias nesting is too deep".to_owned())
    }

    fn ty(&self, type_id: u32) -> Result<&Type, String> {
        self.types
            .get(type_id as usize)
            .ok_or_else(|| format!("invalid BTF type id {type_id}"))
    }

    fn name(&self, offset: u32) -> Result<&str, String> {
        let offset = usize_from_u32(offset)?;
        let tail = self
            .strings
            .get(offset..)
            .ok_or_else(|| format!("invalid BTF string offset {offset}"))?;
        let end = tail
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| "unterminated BTF string".to_owned())?;
        std::str::from_utf8(&tail[..end]).map_err(|_| "invalid UTF-8 in BTF string".to_owned())
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, String> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| "truncated BTF data".to_owned())?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| "truncated BTF data".to_owned())?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn usize_from_u32(value: u32) -> Result<usize, String> {
    usize::try_from(value).map_err(|_| "BTF value does not fit usize".to_owned())
}

fn checked_add(left: usize, right: usize) -> Result<usize, String> {
    left.checked_add(right)
        .ok_or_else(|| "BTF offset overflow".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_the_running_kernel_layout_when_btf_is_available() {
        let path = Path::new("/sys/kernel/btf/vmlinux");
        if !path.is_file() {
            return;
        }
        let layout = KernelLayout::from_path(path).expect("supported kernel BTF");
        assert_ne!(layout.task_signal, u32::MAX);
        assert_ne!(layout.signal_pgid, u32::MAX);
        assert_ne!(layout.tty_pgrp, u32::MAX);
        assert_ne!(layout.tty_device, u32::MAX);
        assert_ne!(layout.device_devt, u32::MAX);
    }

    #[test]
    fn rejects_truncated_and_wrong_version_btf() {
        assert!(KernelLayout::from_bytes(&[]).is_err());
        let mut header = [0_u8; 24];
        header[..2].copy_from_slice(&BTF_MAGIC.to_le_bytes());
        header[2] = 2;
        assert!(KernelLayout::from_bytes(&header).is_err());
    }
}
