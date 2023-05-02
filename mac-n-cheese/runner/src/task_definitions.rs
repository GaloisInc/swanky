use std::marker::PhantomData;

use mac_n_cheese_ir::compilation_format::{FieldMacType, FieldTypeMacVisitor, TaskKind};
use mac_n_cheese_party::Party;
use mac_n_cheese_vole::{mac::MacTypes, specialization::SmallBinaryFieldSpecialization};
use scuttlebutt::field::{IsSubFieldOf, SmallBinaryField, F2};

use crate::{
    task_framework::TaskDefinition,
    types::{visit_type, TypeVisitor},
};

mod add;
mod assert_multiplication;
mod assert_zero;
mod base_vole;
mod constant;
mod copy;
mod fix;
mod linear;
mod vole_extend;
mod xor4;

pub trait TaskDefinitionHelper<P: Party> {
    type UnspecDefn<T: MacTypes>: TaskDefinition<P>;
    type SmallBinaryDefn<TF: SmallBinaryField>: TaskDefinition<P>
    where
        F2: IsSubFieldOf<TF>;
}

pub trait TaskDefinitionVisitor<P: Party>: Sized {
    type Output;
    fn visit<T: TaskDefinition<P>>(self) -> Self::Output;

    fn visit_helper<T: TaskDefinitionHelper<P>>(self, ty: FieldMacType) -> Self::Output {
        struct Visitor<P: Party, V: TaskDefinitionVisitor<P>, T: TaskDefinitionHelper<P>>(
            V,
            PhantomData<(T, P)>,
        );

        impl<P: Party, V: TaskDefinitionVisitor<P>, T: TaskDefinitionHelper<P>> FieldTypeMacVisitor
            for Visitor<P, V, T>
        {
            type Output = V::Output;
            fn visit_small_binary<TF: SmallBinaryField>(self) -> Self::Output
            where
                F2: IsSubFieldOf<TF>,
            {
                self.0.visit::<T::SmallBinaryDefn<TF>>()
            }
            fn visit<
                VF: scuttlebutt::field::FiniteField + scuttlebutt::field::IsSubFieldOf<TF>,
                TF: scuttlebutt::field::FiniteField,
                S: mac_n_cheese_vole::specialization::FiniteFieldSpecialization<VF, TF>,
            >(
                self,
            ) -> Self::Output {
                self.0.visit::<T::UnspecDefn<(VF, TF, S)>>()
            }
        }
        ty.visit(Visitor::<P, Self, T>(self, PhantomData))
    }
}

macro_rules! unspecialized_task_defn {
    ($t:ident, $ty:ident, $($defn:ident)::*) => {{
        struct Wrapper<P: Party>(PhantomData<P>);
        impl<P: Party> TaskDefinitionHelper<P> for Wrapper<P> {
            type UnspecDefn<T: MacTypes> = $($defn)::*<P, T>;
            type SmallBinaryDefn<TF: SmallBinaryField>
                = $($defn)::*<P, (F2, TF, SmallBinaryFieldSpecialization)>
                where
                    F2: IsSubFieldOf<TF> ;
        }
        $t.visit_helper::<Wrapper<_>>($ty)
    }};
}

pub fn visit_task_definition<P: Party, T: TaskDefinitionVisitor<P>>(
    kind: TaskKind,
    t: T,
) -> T::Output {
    match kind {
        TaskKind::Constant(ty) => unspecialized_task_defn!(t, ty, constant::ConstantTask),
        TaskKind::Fix(ty) => unspecialized_task_defn!(t, ty, fix::FixTask),
        TaskKind::Copy(ty) => {
            struct V<P: Party, T: TaskDefinitionVisitor<P>>(T, PhantomData<P>);
            impl<P: Party, T: TaskDefinitionVisitor<P>> TypeVisitor for V<P, T> {
                type Output = T::Output;
                fn visit<U: 'static + Send + Sync + Copy>(self) -> Self::Output {
                    self.0.visit::<copy::CopyTask<P, U>>()
                }
            }
            visit_type::<P, _>(ty, V(t, PhantomData))
        }
        TaskKind::Add(ty) => unspecialized_task_defn!(t, ty, add::AddTask),
        TaskKind::Xor4(ty) => {
            struct V<P: Party, T: TaskDefinitionVisitor<P>>(T, PhantomData<P>);
            impl<P: Party, T: TaskDefinitionVisitor<P>> FieldTypeMacVisitor for V<P, T> {
                type Output = T::Output;
                fn visit_small_binary<TF: SmallBinaryField>(self) -> Self::Output
                where
                    F2: IsSubFieldOf<TF>,
                {
                    self.0.visit::<xor4::Xor4Task<P, TF>>()
                }
                fn visit<
                    VF: scuttlebutt::field::FiniteField + IsSubFieldOf<TF>,
                    TF: scuttlebutt::field::FiniteField,
                    S: mac_n_cheese_vole::specialization::FiniteFieldSpecialization<VF, TF>,
                >(
                    self,
                ) -> Self::Output {
                    panic!("Xor4 can only be called for small binary fields")
                }
            }
            ty.visit(V(t, PhantomData))
        }
        TaskKind::Linear(ty) => unspecialized_task_defn!(t, ty, linear::LinearTask),
        TaskKind::AssertZero(ty) => unspecialized_task_defn!(t, ty, assert_zero::AssertZeroTask),
        TaskKind::AssertMultiplication(ty) => {
            struct Wrapper<P: Party>(PhantomData<P>);
            impl<P: Party> TaskDefinitionHelper<P> for Wrapper<P> {
                type UnspecDefn<T: MacTypes> = assert_multiplication::AssertMultiplyNoSpec<P, T>;
                type SmallBinaryDefn<TF: SmallBinaryField>
                = assert_multiplication::AssertMultiplySmallBinary<P, TF>
                where
                    F2: IsSubFieldOf<TF> ;
            }
            t.visit_helper::<Wrapper<P>>(ty)
        }
        TaskKind::BaseSvole(ty) => unspecialized_task_defn!(t, ty, base_vole::BaseVoleTask),
        TaskKind::VoleExtension(ty) => unspecialized_task_defn!(t, ty, vole_extend::VoleExtendTask),
    }
}
