use hanabi_configs::Lex;

const INPUT: &[u8; 85] =
    b"[asd.we]\n[t43r\\] ca.43we\\.e3]\r\n [ \\...\\]  \\.  \\]..]    \n  #fqe#t4wrv\r\nfavdrd=rh\\=fdvs";
fn main() {
    let mut lex = Lex::new(INPUT);
    let tokens = lex.lex();
    println!("{:?}", tokens);
}
