package main

import (
	"encoding/json"
	"fmt"

	"math/big"
	"os"
	"time"

	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type SnarkProver struct {
	r1cs_circuit constraint.ConstraintSystem
	pk           groth16.ProvingKey
	vk           groth16.VerifyingKey
}

func (obj *SnarkProver) init_circuit_keys(inputdir string) error {
	if obj.r1cs_circuit != nil {
		return nil
	}

	circuitPath := inputdir + "/circuit"
	pkPath := inputdir + "/proving.key"
	vkPath := inputdir + "/verifying.key"
	_, err := os.Stat(circuitPath)

	if os.IsNotExist(err) {
		commonCircuitData := types.ReadCommonCircuitData(inputdir + "/common_circuit_data.json")
		proofWithPisData := types.ReadProofWithPublicInputs(inputdir + "/proof_with_public_inputs.json")
		proofWithPis := variables.DeserializeProofWithPublicInputs(proofWithPisData)

		verifierOnlyCircuitRawData := types.ReadVerifierOnlyCircuitData(inputdir + "/verifier_only_circuit_data.json")
		verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(verifierOnlyCircuitRawData)

		circuit := verifier.ExampleVerifierCircuit{
			Proof:                   proofWithPis.Proof,
			PublicInputs:            proofWithPis.PublicInputs,
			VerifierOnlyCircuitData: verifierOnlyCircuitData,
			CommonCircuitData:       commonCircuitData,
		}

		var builder frontend.NewBuilder = r1cs.NewBuilder
		obj.r1cs_circuit, _ = frontend.Compile(ecc.BN254.ScalarField(), builder, &circuit)
		fR1CS, _ := os.Create(circuitPath)
		obj.r1cs_circuit.WriteTo(fR1CS)
		fR1CS.Close()
	} else {
		fCircuit, err := os.Open(circuitPath)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		obj.r1cs_circuit = groth16.NewCS(ecc.BN254)
		obj.r1cs_circuit.ReadFrom(fCircuit)
		fCircuit.Close()
	}

	_, err = os.Stat(pkPath)
	if os.IsNotExist(err) {
		obj.pk, obj.vk, err = groth16.Setup(obj.r1cs_circuit)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		fPK, _ := os.Create(pkPath)
		obj.pk.WriteTo(fPK)
		fPK.Close()

		if obj.vk != nil {
			fVK, _ := os.Create(vkPath)
			obj.vk.WriteTo(fVK)
			fVK.Close()
		}
	} else {
		obj.pk = groth16.NewProvingKey(ecc.BN254)
		obj.vk = groth16.NewVerifyingKey(ecc.BN254)
		fPk, err := os.Open(pkPath)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		obj.pk.ReadFrom(fPk)

		fVk, err := os.Open(vkPath)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		obj.vk.ReadFrom(fVk)
		defer fVk.Close()
	}
	return nil
}

func (obj *SnarkProver) groth16ProofWithCache(r1cs constraint.ConstraintSystem, inputdir, outputdir string) error {
	proofWithPisData := types.ReadProofWithPublicInputs(inputdir + "/proof_with_public_inputs.json")
	proofWithPis := variables.DeserializeProofWithPublicInputs(proofWithPisData)

	verifierOnlyCircuitRawData := types.ReadVerifierOnlyCircuitData(inputdir + "/verifier_only_circuit_data.json")
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(verifierOnlyCircuitRawData)

	assignment := verifier.ExampleVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
	}

	start := time.Now()
	fmt.Println("Generating witness", start)
	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	fmt.Printf("frontend.NewWitness cost time: %v ms\n", time.Since(start).Milliseconds())
	publicWitness, _ := witness.Public()

	start = time.Now()
	fmt.Println("Creating proof", start)
	proof, err := groth16.Prove(r1cs, obj.pk, witness)
	fmt.Printf("groth16.Prove cost time: %v ms\n", time.Since(start).Milliseconds())
	if err != nil {
		return err
	}

	if obj.vk == nil {
		return fmt.Errorf("vk is nil, means you're using dummy setup and we skip verification of proof")
	}

	start = time.Now()
	fmt.Println("Verifying proof", start)
	err = groth16.Verify(proof, obj.vk, publicWitness)
	fmt.Printf("groth16.Verify cost time: %v ms\n", time.Since(start).Milliseconds())
	if err != nil {
		return err
	}

	fContractProof, _ := os.Create(outputdir + "/snark_proof_with_public_inputs.json")
	_, bPublicWitness, _, _ := groth16.GetBn254Witness(proof, obj.vk, publicWitness)
	nbInputs := len(bPublicWitness)

	type ProofPublicData struct {
		Proof         groth16.Proof
		PublicWitness []string
	}
	proofPublicData := ProofPublicData{
		Proof:         proof,
		PublicWitness: make([]string, nbInputs),
	}
	for i := 0; i < nbInputs; i++ {
		input := new(big.Int)
		bPublicWitness[i].BigInt(input)
		proofPublicData.PublicWitness[i] = input.String()
	}
	proofData, _ := json.Marshal(proofPublicData)
	fContractProof.Write(proofData)
	fContractProof.Close()
	return nil
}

func (obj *SnarkProver) Prove(inputdir string, outputdir string) error {
	if err := obj.init_circuit_keys(inputdir); err != nil {
		return err
	}

	return obj.groth16ProofWithCache(obj.r1cs_circuit, inputdir, outputdir)
}
