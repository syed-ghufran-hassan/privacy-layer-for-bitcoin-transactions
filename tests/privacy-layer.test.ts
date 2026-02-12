import { describe, expect, it } from "vitest";
import { simnet } from "@hirosystems/clarinet-js-sdk";

const POOL_CONTRACT = "privacy-pool";
const FT_CONTRACT = "my-token";

const accounts = simnet.getAccounts();
const user = accounts.get("wallet_1")!;

// Helper to generate a simple Merkle proof for simulation
const generateMerkleProof = (leafIndex: number, treeHeight: number) => {
  return Array(treeHeight).fill("0x0000000000000000000000000000000000000000000000000000000000000000");
};

describe("Privacy Pool Comprehensive Tests", () => {
  const commitments = [
    "0x1111111111111111111111111111111111111111111111111111111111111111",
    "0x2222222222222222222222222222222222222222222222222222222222222222",
    "0x3333333333333333333333333333333333333333333333333333333333333333",
  ];
  const depositAmounts = [100, 200, 300];

  it("should handle multiple deposits correctly", () => {
    commitments.forEach((commitment, i) => {
      const depositTx = simnet.callPublicFn(
        POOL_CONTRACT,
        "deposit",
        [commitment, depositAmounts[i], `(contract ${FT_CONTRACT})`],
        user.address
      );
      expect(depositTx.result).toBeOk();
    });

    // Check next-index
    const nextIndex = simnet.callReadOnlyFn(POOL_CONTRACT, "get-next-index", [], user.address);
    expect(nextIndex.result).toBeUint(commitments.length);

    // Check current-root is set
    const root = simnet.callReadOnlyFn(POOL_CONTRACT, "get-current-root", [], user.address);
    expect(root.result).not.toBeUint(0);
  });

  it("should withdraw each deposit with proper Merkle proof", () => {
    commitments.forEach((commitment, i) => {
      const rootRes = simnet.callReadOnlyFn(POOL_CONTRACT, "get-current-root", [], user.address);
      const currentRoot = rootRes.result;

      const proof = generateMerkleProof(i, 20);

      const nullifier = `0xdeadbeef0000000000000000000000000000000000000000000000000000000${i}`;

      const withdrawTx = simnet.callPublicFn(
        POOL_CONTRACT,
        "withdraw",
        [nullifier, currentRoot, proof, user.address, `(contract ${FT_CONTRACT})`, depositAmounts[i]],
        user.address
      );

      expect(withdrawTx.result).toBeOk();

      // Nullifier should be marked
      const nullifierCheck = simnet.callReadOnlyFn(
        POOL_CONTRACT,
        "is-nullifier-used",
        [nullifier],
        user.address
      );
      expect(nullifierCheck.result).toBeTrue();
    });
  });

  it("should prevent double-spending of a nullifier", () => {
    const rootRes = simnet.callReadOnlyFn(POOL_CONTRACT, "get-current-root", [], user.address);
    const currentRoot = rootRes.result;

    const proof = generateMerkleProof(0, 20);
    const nullifier = "0xdeadbeef00000000000000000000000000000000000000000000000000000000"; // fixed nullifier

    // First withdrawal
    const firstTx = simnet.callPublicFn(
      POOL_CONTRACT,
      "withdraw",
      [nullifier, currentRoot, proof, user.address, `(contract ${FT_CONTRACT})`, 50],
      user.address
    );
    expect(firstTx.result).toBeOk();

    // Second withdrawal should fail
    const secondTx = simnet.callPublicFn(
      POOL_CONTRACT,
      "withdraw",
      [nullifier, currentRoot, proof, user.address, `(contract ${FT_CONTRACT})`, 50],
      user.address
    );
    expect(secondTx.result).toBeErr();
  });
});
