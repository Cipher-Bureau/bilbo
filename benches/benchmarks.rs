use std::io::Write;

use criterion::{criterion_group, criterion_main, Criterion};
use bilbo::rsa::PickLock;
use bilbo::entropy::Shannon;
use num_bigint::{BigInt, Sign};
use openssl::bn::BigNum;

fn benchmark_lock_pick_weak_private_to_crack_large_weak_rsa(c: &mut Criterion) {
    c.bench_function("benchmark_lock_pick_weak_private_to_crack_large_weak_rsa", |b| { 
        
        let Ok(large_n) = BigNum::from_dec_str("24051723933323373230335109652699872887260372863633030520380856590934224554506308944154529656903683098544282868895265857723676740447085769973038138116162852753658181861191950778361549639563565516085451073539560657386103501608592321148669427604194877552133864887585897064910317370632491325912646759075452895764136071794899761625652745642888012193592843601786282707419064157922868466879644136792854722277212465067471658496818060980989808791352963906077940588038623347540668963885547785982543883250789113853569537794783330309654648546163063571756203834919697878945651911998161025323667873893944714006021586935213636888431") else {
            assert!(false);
            return;
        };
        let Ok(large_d) = BigNum::from_dec_str("20859605057389981400415296665239606253551311979432043299936333792698939369418558891569637169366135826146428643134992692481438916188899523620207130817470747633629513081286743218201811495234043370443885950972963184234382668232155560092302387896834347699555010854105235260577040893379009940545782216749159515118484219566373157731404293321389017417036945992984437162056145246504943473128453889715274064071687926343900718250671226003207988553491071490774949729393790264296526140962891140650428560103645538027632465103573248308915991466476312603275778085679414182339076676621372222055380237829179961993191380693342799887257") else {
            assert!(false);
            return;
        };

        let n=  BigInt::from_bytes_be(Sign::Plus, &large_n.to_vec()); 
        let e = BigInt::new(Sign::Plus, vec![65537]);
        let d = BigInt::from_bytes_be(Sign::Plus, &large_d.to_vec()); 

        let pl = PickLock::from_exponent_and_modulus(e.clone(), n.clone());
        b.iter(|| {
            let Ok(res) = pl.try_lock_pick_weak_private() else {
                assert!(false);
                return;
            };
            assert_eq!(res, d);
        });
    });
}

fn benchmark_lock_pick_weak_private_to_not_be_able_to_crack_strong_small_rsa(c: &mut Criterion) {
    c.bench_function("benchmark_lock_pick_weak_private_to_not_be_able_to_crack_strong_large_rsa", |b| { 
        
        const PUBLIC_KEY_SAMPLE: &'static str = "-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMp2Z+WFY2ygdgPMnWpJNxqtuweA1nix
kTirAEQ+F3NKfNEdR9J/+Rq+2ViT3wnamtuBG+10SKuKjr9FKhh/T0sCAwEAAQ==
-----END PUBLIC KEY-----
        ";

        let Ok(pl) = PickLock::from_pem(&PUBLIC_KEY_SAMPLE) else {
            assert!(false);
            return;
        };

        b.iter(|| {
            let Err(_) = pl.try_lock_pick_weak_private() else {
                assert!(false);
                return;
            };
        });
    });
}

fn benchmark_lock_pick_strong_private_to_crack_strong_small_rsa(c: &mut Criterion) {
    c.bench_function("benchmark_lock_pick_strong_private_to_crack_strong_small_rsa", |b| { 
        
        const PUBLIC_KEY_SAMPLE: &'static str = "-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMp2Z+WFY2ygdgPMnWpJNxqtuweA1nix
kTirAEQ+F3NKfNEdR9J/+Rq+2ViT3wnamtuBG+10SKuKjr9FKhh/T0sCAwEAAQ==
-----END PUBLIC KEY-----
        ";

        let Ok(mut pl) = PickLock::from_pem(&PUBLIC_KEY_SAMPLE) else {
            assert!(false);
            return;
        };
        pl.alter_max_iter(100);

        b.iter(|| {
            let _ = pl.try_lock_pick_strong_private(false);
        });
    });
}

fn benchmark_entropy_calculation(c: &mut Criterion) {
    c.bench_function("benchmark_entropy_calculation", |b| {
        let info_buffer = "+/OPANMQZ1AMsXrp/qP0aXbYLyeI6KaKDNEFLvq3";
        let mut pre = Shannon::new();
        b.iter(|| {
            let _ = pre.write(info_buffer.as_bytes());
            let _ = pre.process();
            let _ = pre.flush();
        })
    });
}

criterion_group!(
    benches,
    benchmark_lock_pick_weak_private_to_crack_large_weak_rsa,
    benchmark_lock_pick_weak_private_to_not_be_able_to_crack_strong_small_rsa,
    benchmark_lock_pick_strong_private_to_crack_strong_small_rsa,
    benchmark_entropy_calculation,
);
criterion_main!(benches);