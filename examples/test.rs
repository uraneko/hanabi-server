use hanabi_configs::{AnalyzeSemantics, AnalyzeSyntax, Lex};

const INPUT: &[u8; 103] =
    b"[asd.we]\n[t43r\\] ca.43we\\.e3]\r\n [ \\...\\]  \\.  \\]..]    \n  #fqe#t4wrv\r\nfavdrd=rh\\=fdvs\n\r4hewds\\=er#vsc./";
fn main() {
    let mut lex = Lex::new(INPUT);
    let tokens = lex.lex().unwrap();
    println!("{:?}", tokens);

    let analyze = AnalyzeSyntax::new(tokens);
    let groups = analyze.analyze().unwrap();
    println!("{:?}", groups);

    let analyze = AnalyzeSemantics::new(groups);
    let components = analyze.analyze().unwrap();
    println!("{:?}", components);
}
