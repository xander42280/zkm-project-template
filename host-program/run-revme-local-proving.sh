export LD_LIBRARY_PATH=/mnt/data/zkm-project-template/sdk/src/local/libsnark:$LD_LIBRARY_PATH  ##Modify it according your template 
export ZKM_PROVER=local
export RUST_LOG=info
export SEG_SIZE=262144
export ELF_PATH=../guest-program/mips-elf/zkm-mips-elf-revme-rust  ##If you using your own mips ELF, please modify the path
export PUBLIC_INPUT_PATH=host-program/test-vectors/244.json    
export OUTPUT_DIR=/tmp/zkm

nohup ../target/release/revme-prove  >./revme-local-proving.log 2>&1 &