use std::fmt::{Debug, Formatter};

#[derive(Clone, Copy, PartialEq)]
pub struct Flags {
    pub overflow_or_less_than_flag: bool,
    pub equality_flag: bool,
    pub greater_than_flag: bool,
}

impl Flags {
    pub const fn empty() -> Self {
        Self {
            overflow_or_less_than_flag: false,
            equality_flag: false,
            greater_than_flag: false,
        }
    }
    pub fn reset(&mut self) {
        self.overflow_or_less_than_flag = false;
        self.equality_flag = false;
        self.greater_than_flag = false;
    }

    pub fn get_set_flags_captions(&self) -> Vec<String> {
        let mut res: Vec<String> = vec![];
        if self.overflow_or_less_than_flag {
            res.push(String::from("lt"))
        }
        if self.equality_flag {
            res.push(String::from("eq"))
        }
        if self.greater_than_flag {
            res.push(String::from("gt"))
        }
        res
    }
}

impl Debug for Flags {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        fn bool_to_sym(b: bool) -> &'static str {
            if b {
                "+"
            } else {
                "-"
            }
        }
        write!(
            f,
            "lt{} eq{} gt{}",
            bool_to_sym(self.overflow_or_less_than_flag),
            bool_to_sym(self.equality_flag),
            bool_to_sym(self.greater_than_flag)
        )
    }
}
