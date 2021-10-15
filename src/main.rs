mod aes;
mod bits;
mod english;
mod pkcs7;
mod set1;
mod set2;
mod set3;

fn main() {

    println!("Running set 1...");
    set1::challenge1();
    set1::challenge2();
    set1::challenge3();
    set1::challenge4();
    set1::challenge5();
    set1::challenge6();
    set1::challenge7();
    set1::challenge8();

    println!("Running set 2...");
    set2::challenge9();
    set2::challenge10();
    set2::challenge11();
    set2::challenge12();
    set2::challenge13();
    set2::challenge14();
    set2::challenge15();
    set2::challenge16();

    println!("Running set 3...");
    set3::challenge17();
    set3::challenge18();
    set3::challenge19();
    set3::challenge20();
}
