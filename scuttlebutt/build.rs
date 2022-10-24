fn main() {
    #[cfg(feature = "ff")]
    {
        use ff_codegen::{PrimeFieldCodegen, ReprEndianness::Little};
        use std::path::Path;
        for mut cg in [
            PrimeFieldCodegen {
                ident: "F384p",
                is_pub: true,
                modulus: "39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319",
                generator: "19",
                endianness: Little,
            },
            PrimeFieldCodegen {
                ident: "F384q",
                is_pub: true,
                modulus: "39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643",
                generator: "19",
                endianness: Little,
            },
            PrimeFieldCodegen {
                ident: "F128p",
                is_pub: true,
                modulus: "340282366920938463463374607431768211297",
                generator: "5",
                endianness: Little,
            },
            PrimeFieldCodegen {
                ident: "F256p",
                is_pub: true,
                modulus: "115792089210356248762697446949407573530086143415290314195533631308867097853951",
                generator: "6",
                endianness: Little,
            },
            PrimeFieldCodegen {
                ident: "Fbls12381",
                is_pub: true,
                modulus: "52435875175126190479447740508185965837690552500527637822603658699938581184513",
                generator: "7",
                endianness: Little,
            },
            PrimeFieldCodegen {
                ident: "Fbn254",
                is_pub: true,
                modulus: "21888242871839275222246405745257275088548364400416034343698204186575808495617",
                generator: "5",
                endianness: Little,
            },
            PrimeFieldCodegen {
                ident: "F2e19x3e26",
                is_pub: true,
                modulus: "1332669751402954753",
                generator: "7",
                endianness: Little,
            },
        ] {
            let path = Path::new(&std::env::var("OUT_DIR").unwrap()).join(format!("ff-{}.rs", cg.ident));
            cg.ident = "Internal";
            std::fs::write(
                &path,
                format!(" \
                    {cg} \
                    #[cfg(test)] pub(super) const MODULUS_STRING: &str = {:?}; \
                    #[cfg(test)] pub(super) const GENERATOR_STRING: &str = {:?}; \
                ", cg.modulus, cg.generator).as_bytes(),
            )
            .unwrap()
        }
    }
    println!("cargo:rerun-if-changed=build.rs");
}
