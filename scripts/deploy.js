const { ethers } = require("hardhat");

async function deployPVerifier() {
    const Verifier = await ethers.getContractFactory("PVerifier");
    const verifier = await Verifier.deploy();
    await verifier.deployed();
    console.log("PVerifier address:", verifier.address);
}

async function deployRVerifier() {
    const Verifier = await ethers.getContractFactory("RVerifier");
    const verifier = await Verifier.deploy();
    await verifier.deployed();
    console.log("RVerifier address:", verifier.address);
}

async function main() {
    await deployPVerifier();
    await deployRVerifier();
}

main();