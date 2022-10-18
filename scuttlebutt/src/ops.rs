/// Macro for implementing a binary operation trait.
macro_rules! binop {
    ($trait:ident, $name:ident, $assign:path, $f:ident) => {
        impl std::ops::$trait<$f> for $f {
            type Output = $f;

            #[inline]
            #[allow(unused_imports)]
            fn $name(mut self, rhs: $f) -> Self::Output {
                use std::ops::$trait;
                $assign(&mut self, rhs);
                self
            }
        }
        impl<'a> std::ops::$trait<$f> for &'a $f {
            type Output = $f;

            #[inline]
            #[allow(unused_imports)]
            fn $name(self, rhs: $f) -> Self::Output {
                use std::ops::$trait;
                let mut this = self.clone();
                $assign(&mut this, rhs);
                this
            }
        }
        impl<'a> std::ops::$trait<&'a $f> for $f {
            type Output = $f;

            #[inline]
            #[allow(unused_imports)]
            fn $name(mut self, rhs: &'a $f) -> Self::Output {
                use std::ops::$trait;
                $assign(&mut self, rhs);
                self
            }
        }
        impl<'a> std::ops::$trait<&'a $f> for &'a $f {
            type Output = $f;

            #[inline]
            fn $name(self, rhs: &'a $f) -> Self::Output {
                let mut this = self.clone();
                $assign(&mut this, rhs);
                this
            }
        }
    };
}
pub(crate) use binop;

// Macro for implementing an assign operation trait.
macro_rules! assign_op {
    ($tr:ident, $op:ident, $f:ident) => {
        impl std::ops::$tr<$f> for $f {
            #[inline]
            #[allow(unused_imports)]
            fn $op(&mut self, rhs: $f) {
                use std::ops::$tr;
                self.$op(&rhs)
            }
        }
    };
}
pub(crate) use assign_op;
