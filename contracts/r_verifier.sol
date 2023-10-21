// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}

contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x1da756c4939a412de14c38e3e5016e42d1ef74ad4ab7c8b52a0bf4ce218ab945), uint256(0x2e5d2b8e9b8f633ba348c51bd2e3bbd259ac7301f62a371e88a37da28d9159de));
        vk.beta = Pairing.G2Point([uint256(0x0f0c81eee4e1b5c222a7013e1bae343384c9764f73c2e286eecd5a050b0b5a14), uint256(0x1620070406d52d49af7f607f398eb13dc661e07312f251729e70d968f774d93e)], [uint256(0x2c424ce4302f90c25b4b05ef6a46afde222fcec6fe2b9711fbb39c39c6cd18c7), uint256(0x04590c583265afdcc7f665fefe1b7b4908b3d17ba5354a62f629dcb29f96e8ab)]);
        vk.gamma = Pairing.G2Point([uint256(0x2656b8117973ed09f84c47847418844e9473d0d5e84a85af330b36b492b3723c), uint256(0x006488ea3a0d4c22e19fc018bccecd698159e00152dc423e0192f7897bd8c32f)], [uint256(0x1ff630baa8c291ad72fd7b805846bf2e4a650b0fd4e26fefbe985c9e59585de3), uint256(0x0766002f81f8c8376ddd5ed40539e61bc71b7fa526127d26bab6abd3a1cf6cad)]);
        vk.delta = Pairing.G2Point([uint256(0x00b209ba40b24fb05a19e0c1456bdbb4a168aa511acc53862635b74600378ea6), uint256(0x10c7831426268f014e4f40b966555ea237e0bc98cabbef97a3c071faf6d54ed2)], [uint256(0x1b7aa39643cf9dc8bbcc5a7324e88fa8c791d028cea395e840174f19f0a9e43c), uint256(0x089de6bef4dd141eb07ce18684e5af7f5ef35881765f59913f22ff34130d6e6b)]);
        vk.gamma_abc = new Pairing.G1Point[](21);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x087b8a59b617a6aec063a78441bb312426bb6f7ceb74cbec1212ac67dadb3c10), uint256(0x1fa7746cd99525826ec06022a4f9942c034a7d65ea78819c8250a01c28ff53ba));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x075c4586b563ae0b95aa6f2b8c8c17a939f3721c7a904d32b924efface7bed3e), uint256(0x133e16fcfb8647f57a974fe9b1e7e3d89323ae6192aec56c33b2ae1d30774c7a));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x09798eb3311df7796e433e147396db6cb242bbac713659322dd4cddb1eff9cc5), uint256(0x050a07c48ba3e6d9d17ad5a450b4a70b6bc440a7a7e1ba717f33d734c225ddd0));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x2fd9a6ed7736592b9bfa2381694134ca9b951f3190fa0d078b751b6f4a4d3000), uint256(0x06ca2045016814862549f2614a6f7a8c49474e76be131ed303dc48ff512ec123));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2ef780ca63559c773ed1fbdba15bd627d62f419a153525e7c99cc47a8d7e5b80), uint256(0x2e686f7a282e3f93180da09af4655601a103c7e2dfa80cb79cb71297a6d063e0));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x06deaac03b9e409f0d4d608ca99b778ec66368560f40423f5ef8c98655320f8a), uint256(0x1c4f1ce5eae6e9e701338d7f007ca67df87a97e10eb22fbc3b4339f544d53657));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x25fddd8b40adcabf89655b8042c96ffb80b51e9475d6a76db1f80320ed63910b), uint256(0x1237511f2b28d3aed4c672176bb07f131b4f1219caeae71351e0c35bc4aa6942));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x078bb905b8ffdb98afb692fd39c201b25dcae89f3d1dc6023aa40e72b796ac5a), uint256(0x16f13b56f42b3735c8a3348ccaf29753e58fff17e381a7ca5583f96fccbb2611));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x1f1709bc45572090e5276575c57f122e6b5ed5479f7096c149c2de6e9930c58e), uint256(0x07179a680c03af21c2ad4e9015bff0b68be8c440f84392965c85794df17594f6));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x163811bad73aba8d727ea36134bc642378d9a52052caa8fea5fb86e74d99325c), uint256(0x1e7dfca2d1e902b08be4e2b9bd59bc40c7e0d21e8474aac913e063bf0ddb4158));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x244e0354e4b47f9eb9275cb77f60f8e5bd9fe865eb2c611d54e9a9fd00ce0b69), uint256(0x0bdcb5670e1f6671d84b3fbee2f547d62c9c932f2799822b0b2c0ff46353ae1f));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x10fdd424bd37ffa56c83b323c3a7cd4d739748381895ee85b5e602592d83beac), uint256(0x2156c65f099973da8c07147080f45926ef177700775ac610d77cb8075d08ef6d));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x27dc0cf04faf50da3a13aa9e2b62fd9bc73f814b6e5e78b44218657edba626dd), uint256(0x2e3ea81cce92bdce280a9e804bbed844f4818cb014981cfeba5bfe5dfa90da61));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x0b272c95d77b3d89f80ca8a86de6efad506a3178ff41d7be2f27d842dd603b7a), uint256(0x28e481b221203ccad8a629c737a5710ef4206dcd619992eb0dd3e516b123e5a0));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x0ef423e266c1a7d84e2fe18fee413de63c712af616d639042047935793581c3e), uint256(0x155339af54a9925e36be19b86b4373d2a3f60a8cd90e749ff545bc55d22a2dac));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x110584316f5f0bd2c88a7076b14add11ee5454fee4dc8766901087b7923cf6b4), uint256(0x30241a1cb6144cff48cb14205c74dd87f2f37173a03caf29fb453d8f7b4290b8));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x11cb56538b6aa47cff269c6d795ce6a25d1522a6f06c4eac965ad6936b07e2e3), uint256(0x1ad7077d6efe47751dc144e287aba0d6215a11aa20b1ad7437a80392be34cab6));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x0d72a469e0609bc640713224759c3e255103aa02e9251aa1fd8323ae89a452cf), uint256(0x1fdbca334f19c5b79c432e48513121fa7f4a2d62bb2683966d392556c3930fbb));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x15472b821f4cccde242af712078015c58fad2621500c74f073afc31246667b26), uint256(0x0efcb3e0b53ba8ce650b2d57c5676f6ce3199de8c3967c5ba85c842ae369b7df));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x2b13dd8e73b3658a6346d2920c335e27d4cc67e2309f4ea1a27fd8ff606bd1c7), uint256(0x0c2e3c71abd51fb0f52ef8a15c611fc3140e4cf2acc37202f8011de7f5702a9f));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x24104777672569f34f475b2ff08fef049e4cd50a31b6cd7754db663be86bc3bc), uint256(0x21bd772d22ffa11b367451c02bb39d964547a04a34cf3715bc6be0a8492fdc67));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[20] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](20);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}
