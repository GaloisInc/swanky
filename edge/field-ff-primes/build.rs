use ff_codegen::{PrimeFieldCodegen, ReprEndianness::Little};
use num_bigint::BigUint;
use sha2::Digest;
use std::collections::HashMap;
use std::fmt::Write;
use std::path::Path;
use std::str::FromStr;
use std::sync::Mutex;
fn to_hex(buf: &[u8]) -> String {
    let mut out = String::new();
    for byte in buf {
        write!(out, "{byte:x}").unwrap();
    }
    out
}

fn main() {
    let requests = vec![
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
            ident: "F127p",
            is_pub: true,
            modulus: "170141183460469231731687303715884105727",
            generator: "43",
            endianness: Little,
        },
        PrimeFieldCodegen {
            ident: "Frs127p",
            is_pub: true,
            modulus: "170141183460469231731687303715884105217",
            generator: "5",
            endianness: Little,
        },
        PrimeFieldCodegen {
            ident: "F32p",
            is_pub: true,
            modulus: "4294966769",
            generator: "3",
            endianness: Little,
        },
        PrimeFieldCodegen {
            ident: "F61p",
            is_pub: true,
            modulus: "2305843009213693951",
            generator: "37",
            endianness: Little,
        },
        PrimeFieldCodegen {
            ident: "F64p",
            is_pub: true,
            modulus: "18446744073709551521",
            generator: "3",
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
            ident: "Secp256k1",
            is_pub: true,
            modulus: "115792089237316195423570985008687907853269984665640564039457584007908834671663",
            generator: "3",
            endianness: Little,
        },
        PrimeFieldCodegen {
            ident: "Secp256k1order",
            is_pub: true,
            modulus: "115792089237316195423570985008687907852837564279074904382605163141518161494337",
            generator: "7",
            endianness: Little,
        },
        PrimeFieldCodegen {
            ident: "F256p",
            is_pub: true,
            modulus: "115792089237316195423570985008687907853269984665640564039457584007913129637873",
            generator: "3",
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
        PrimeFieldCodegen {
            ident: "F400p",
            is_pub: true,
            modulus: "2582249878086908589655919172003011874329705792829223512830659356540647622016841194629645353280137831435903171972747492783",
            generator: "5",
            endianness: Little,
        },
        PrimeFieldCodegen {
            ident: "Frs512p",
            is_pub: true,
            modulus: "13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433644711116801",
            generator: "2653135687665933732116392076509140650815216084673071913799274672109843317862972825520025532916796169010684541040936963921422520982516932732201540090815717",
            endianness: Little,
        },
        PrimeFieldCodegen {
            ident: "Frs1024p",
            is_pub: true,
            modulus: "179769313486231590772930519078902473361797697894230657273430081157732675805500963132708477322407536021120113879871393357658789768814416622492847430639474124377767893424865485276302219601246094119453082952085005768838150682342462881473913110540827237163350510684586298239947245938479716304835356321244742942721",
            generator: "22832505786862897753078148751680270733331860838970131534296869387398223592305000977443419498510768487946698509029933304554893106469031756257836068742741753857530940829270365898820714812107283520410028918716711472464971819042262220977649135314963906236952025626572871773751662397013380098453055619232777035002",
            endianness: Little,
        },
        PrimeFieldCodegen {
            ident: "Frs2048p",
            is_pub: true,
            modulus: "32317006071311007300714876688669951960444102669715484032130345427524655138867890893197201411522913463688717960921898019494119559150490921095088152386448283120630877367300996091750197750389652106796057638384067568276792218642619756161838094338476170470581645852036305042887575891541065808607552399123930385521914333389668342420684974786564569494856176035326322058077805659331026192708460314150258592864177116725943603718461857357598351152301645904403697613233287231227125684710820209725157101726931323469678542580656697935045997268352998638215525166389437335543602135433229604645318478604952148193555853608091773829121",
            generator: "19291268532031067759301150772075288269172959059986750385164537061588752247453891949112826850975506531846971683485645819908013063087583765064790667687829608302309585343733315555577226135707678370442081781594564425075189427722345213073755396389829538731742120536104661349993511406620515573999970364358896506283192130919939719398055592064934576695989980001196194447336815253162667681945826745986282495032064633858026988864668286535558680800954268566664168613432327544436290907225483521470116696952512531713709956495386762365556231280187748786807690833120859284395608997017327545790909648604065027828113847539067671506549",
            endianness: Little,
        },
        // PrimeFieldCodegen {
        //     ident: "Frs4096p",
        //     is_pub: true,
        //     modulus: "1044388881413152506691752710716624382579964249047383780384233483283953907971557456848826811934997558340890106714439262837987573438185793607263236087851365277945956976543709998340361590134383718314428070011855946226376318839397712745672334684344586617496807908705803704071284048740118609114467977783598029006686938976881787785946905630190260940599579453432823469303026696443059025015972399867714215541693835559885291486318237914434496734087811872639496475100189041349008417061675093668333850551032972088269550769983616369411933015213796825837188091833656751221318492846368125550225998300412344784862595674492194617023806505913245610825731835380087608622102834270197698202313169017678006675195485079921636419370285375124784014907159135459982790513399611551794271106831134090584272884279791554849782954323534517065223269061394905987693002122963395687782878948440616007412945674919823050571642377154816321380631045902916136926708342856440730447899971901781465763473223850267253059899795996090799469201774624817718449867455659250178329070473119433165550807568221846571746373296884912819520317457002440926616910874148385078411929804522981857338977648103126085903001302413467189726673216491511131602920781738033436090243804708331937773649921",
        //     generator: "661116002378496070632204327520180531229884591342196550548728348889932751513724944289698237713067706900813400836486358120970071286369123762317908198637968901859354324473589772911113983639371232203073419464672446484894198554307456766828137741037269923904965016789857059962326474481647230145761407243484721427921901466576848867678175563658924958764838117424367532286051199313584659556944423726297836513993700081117357168913889220894117310060266478025302873023864246518692907657216419375206424142417591747130142394410009344625233502303177686612333995227661716648914007090627187341157314111492489467797704579803028627274577884005217158222805268126417263893361413343450683133936654549033155202827771294074265309529727921391440704623788872807590064457780722052446280938651128594824953284322877989028248677636084908666601869460996215497303487251768679344620313765979580045688474312838302932543396108015321341548551896991661643980441497396170051035904644095337944826640012010731134572739883143530321055330201225938961206973055436326262752855360358670516267215178406784094165408355782861184429335186889669416783409991871612140613212789103635489545298470228856091259361931581505889732818111318949591638381451748695740321093481346352371765519550",
        //     endianness: Little,
        // },
    ];
    let cache_dir = if let Ok(swanky_cache_dir) = std::env::var("SWANKY_CACHE_DIR") {
        let cache_dir = Path::new(&swanky_cache_dir).join("finite-field-codegen-v1");
        std::fs::create_dir_all(&cache_dir).unwrap();
        Some(cache_dir)
    } else {
        None
    };
    let out_dir = Path::new(&std::env::var("OUT_DIR").unwrap()).to_path_buf();
    let cache_key = {
        let mut h = sha2::Sha256::new();
        h.update(std::fs::read(std::env::current_exe().unwrap()).unwrap());
        h.finalize()
    };
    let cache_entry = cache_dir.map(|cache_dir| cache_dir.join(to_hex(&cache_key)));
    let outputs = if let Some(cache_entry) = cache_entry
        .as_ref()
        .filter(|cache_entry| cache_entry.exists())
    {
        let mut outputs = HashMap::<String, String>::new();
        for entry in std::fs::read_dir(cache_entry).unwrap() {
            let entry = entry.unwrap();
            outputs.insert(
                entry.file_name().to_str().unwrap().to_string(),
                std::fs::read_to_string(entry.path()).unwrap(),
            );
        }
        outputs
    } else {
        let outputs = Mutex::new(HashMap::<String, String>::new());
        let queue = Mutex::new(requests);
        std::thread::scope(|scope| {
            for _ in 0..num_cpus::get().max(1) {
                scope.spawn(|| {
                    while let Some(mut cg) = {
                        let mut guard = queue.lock().unwrap();
                        let out = guard.pop();
                        std::mem::drop(guard);
                        out
                    } {
                        let filename = format!("ff-{}.rs", cg.ident);
                        cg.ident = "Internal";
                        let mut out = String::new();
                        write!(out, "{cg}").unwrap();
                        write!(
                            out,
                            "#[cfg(test)] pub(super) const MODULUS_STRING: &str = {:?};",
                            cg.modulus
                        )
                        .unwrap();
                        write!(
                            out,
                            "pub(super) const MODULUS_BYTES: &[u8] = &{:?};",
                            BigUint::from_str(cg.modulus)
                                .unwrap()
                                .to_bytes_le()
                                .as_slice()
                        )
                        .unwrap();
                        write!(
                            out,
                            "#[cfg(test)] pub(super) const GENERATOR_STRING: &str = {:?};",
                            cg.generator
                        )
                        .unwrap();
                        outputs.lock().unwrap().insert(filename, out);
                    }
                });
            }
        });
        outputs.into_inner().unwrap()
    };
    for (k, v) in outputs.iter() {
        std::fs::write(out_dir.join(k), v.as_bytes()).unwrap();
    }
    if let Some(cache_entry) = cache_entry
        .as_ref()
        .filter(|cache_entry| !cache_entry.exists())
    {
        let tmpdir = tempfile::TempDir::new_in(cache_entry.parent().unwrap()).unwrap();
        for (k, v) in outputs.iter() {
            std::fs::write(tmpdir.path().join(k), v.as_bytes()).unwrap();
        }
        std::fs::rename(tmpdir.keep(), cache_entry).unwrap();
    }
    println!("cargo:rerun-if-changed=build.rs");
}
