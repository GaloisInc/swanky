use std::{any::TypeId, marker::PhantomData};

use bytemuck::TransparentWrapper;
use mac_n_cheese_ir::compilation_format::{FieldTypeMacVisitor, Type};
use mac_n_cheese_party::Party;
use mac_n_cheese_vole::{
    mac::{Mac, MacTypes},
    specialization::FiniteFieldSpecialization,
};
use scuttlebutt::field::{FiniteField, IsSubFieldOf};

#[repr(transparent)]
#[derive(Clone, Copy, Default)]
pub struct RandomMac<P: Party, T: MacTypes>(pub Mac<P, T>);
// Switch to using derive when https://github.com/Lokathor/bytemuck/pull/146 is released
unsafe impl<P: Party, T: MacTypes> TransparentWrapper<Mac<P, T>> for RandomMac<P, T> {}

pub trait TypeVisitor {
    type Output;
    fn visit<T: 'static + Send + Sync + Copy>(self) -> Self::Output;
}

pub fn visit_type<P: Party, T: TypeVisitor>(ty: Type, v: T) -> T::Output {
    match ty {
        Type::RandomMac(x) => {
            struct V<P: Party, T: TypeVisitor>(T, PhantomData<P>);
            impl<P: Party, T: TypeVisitor> FieldTypeMacVisitor for V<P, T> {
                type Output = T::Output;
                fn visit<
                    VF: FiniteField + IsSubFieldOf<TF>,
                    TF: FiniteField,
                    S: FiniteFieldSpecialization<VF, TF>,
                >(
                    self,
                ) -> Self::Output {
                    self.0.visit::<RandomMac<P, (VF, TF, S)>>()
                }
            }
            x.visit(V::<P, T>(v, PhantomData))
        }
        Type::Mac(x) => {
            struct V<P: Party, T: TypeVisitor>(T, PhantomData<P>);
            impl<P: Party, T: TypeVisitor> FieldTypeMacVisitor for V<P, T> {
                type Output = T::Output;
                fn visit<
                    VF: FiniteField + IsSubFieldOf<TF>,
                    TF: FiniteField,
                    S: FiniteFieldSpecialization<VF, TF>,
                >(
                    self,
                ) -> Self::Output {
                    self.0.visit::<Mac<P, (VF, TF, S)>>()
                }
            }
            x.visit(V::<P, T>(v, PhantomData))
        }
    }
}

pub fn assert_type_is<P: Party, T: 'static + Send + Sync>(ty: Type) {
    struct V<T: 'static + Send + Sync>(PhantomData<T>);
    impl<T: 'static + Send + Sync> TypeVisitor for V<T> {
        type Output = ();
        fn visit<U: 'static + Send + Sync + Copy>(self) -> Self::Output {
            assert_eq!(TypeId::of::<U>(), TypeId::of::<T>());
        }
    }
    visit_type::<P, _>(ty, V::<T>(PhantomData));
}
