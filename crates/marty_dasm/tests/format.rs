use marty_dasm::{CpuType, DecoderOptions, Format, FormatOptions, NasmFormatter, decoder::Decoder};

#[test]
pub fn format_mnemonic() {
    let bytes = vec![0x01, 0x00];

    let mut dec = Decoder::new(
        bytes.as_slice(),
        DecoderOptions {
            cpu: CpuType::Intel80386,
            ..Default::default()
        },
    );

    let ins = dec.decode_next().expect("decode ok");
    assert_eq!(ins.mnemonic.to_string(), "ADD");

    // make mnemonic-only formatter
    let options = FormatOptions {
        uppercase_mnemonic: true,
        mnemonic_only: true,
        ..Default::default()
    };

    let mut output_string = String::new();
    NasmFormatter.format_instruction(&ins, &options, &mut output_string);

    assert_eq!(output_string, "ADD");
}
