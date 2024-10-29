// SPDX-License-Identifier: GPL-3.0-only
pragma solidity =0.8.24;

import { XApp } from "../pkg/XApp.sol";
import { IERC20 } from "@openzeppelin/contracts/interfaces/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract SILKLockbox is XApp {
    using SafeERC20 for IERC20;

    error Unauthorized();
    error IntentFailed();
    error CancelTimeout();
    error TransferFailed();
    error IntentFulfilled();
    error IncorrectIntent();

    event UserIntent(
        bytes32 guid,
        uint64 destChainId,
        address token,
        uint256 payment,
        uint96 extraNativeTip,
        address to,
        uint128 nativeValue,
        bytes callData
    );
    event FulfilledIntent(bytes32 guid, address solver);
    event CompletedIntent(bytes32 guid, address solverRecipient);

    struct Intent {
        bool fulfilled;
        uint40 timestamp;
        address from;
        uint96 extraNativeTip;
        address token;
        uint64 destChainId;
        address to;
        uint128 nativeValue;
        uint128 payment;
        bytes callData;
    }

    mapping(bytes32 guid => Intent) public intents;
    bytes32 public nextGuid;
    uint24 public cancelTimeout;

    constructor(address omni_, uint8 defaultConfLevel_, uint24 cancelTimeout_) payable XApp(omni_, defaultConfLevel_) {
        nextGuid = bytes32(uint256(1));
        cancelTimeout = cancelTimeout_;
    }

    function wantThing(
        uint64 destChainId,
        address token,
        uint128 nativeValue,
        uint128 payment,
        address to,
        bytes calldata callData
    ) external payable returns (bytes32 guid) {
        // Get and increment guid
        assembly {
            // Load from storage slot
            guid := sload(nextGuid.slot)
            // Increment and store back
            sstore(nextGuid.slot, add(guid, 1))
        }

        // Handle payment in native or ERC20 tokens
        uint96 extraNativeTip;
        if (token != address(0)) {
            IERC20(token).safeTransferFrom(msg.sender, address(this), payment);
            extraNativeTip = uint96(msg.value);
        } else {
            payment = uint128(msg.value);
        }

        intents[guid] = Intent({
            fulfilled: false,
            timestamp: uint40(block.timestamp),
            from: msg.sender,
            extraNativeTip: extraNativeTip,
            token: token,
            destChainId: destChainId,
            to: to,
            nativeValue: nativeValue,
            payment: payment,
            callData: callData
        });
        emit UserIntent(guid, destChainId, token, payment, extraNativeTip, to, nativeValue, callData);
        return guid;
    }

    function doThing(bytes32 guid, uint64 originChainId, address to, bytes calldata callData, address solverRecipient)
        external
        payable
    {
        // Execute intent
        (bool success,) = payable(to).call{ value: msg.value }(callData);
        if (!success) revert IntentFailed(); // Maybe we can tell origin lockbox to allow refund? Can we replay?

        // Compute attestation to validate intent was performed correctly
        bytes32 attestation = keccak256(abi.encode(guid, uint64(block.chainid), to, msg.value, callData));
        bytes memory data = abi.encodeWithSelector(this.ackThing.selector, guid, attestation, solverRecipient);

        // Inform origin lockbox of intent completion
        xcall(originChainId, address(this), data, 200_000);
        // We do not know as of this point if the intent was performed properly
        // We cannot halt further attempts as that would make user intents griefable
        // Do we queue future attempts and wait for an ack-ok to burn guid or ack-fail before processing the next one?
        emit FulfilledIntent(guid, msg.sender);
    }

    function ackThing(bytes32 guid, bytes32 attestation, address solverRecipient) external xrecv {
        // Only lockbox can acknowledge intent completion
        if (xmsg.sender != address(this)) revert Unauthorized();

        // Validate that original intent matches attestation and that it hasn't been fulfilled
        Intent memory intent = intents[guid];
        if (intent.fulfilled) revert IntentFulfilled();
        bytes32 _attestation =
            keccak256(abi.encode(guid, xmsg.sourceChainId, intent.to, intent.nativeValue, intent.callData));
        if (_attestation != attestation) revert IncorrectIntent(); // Do we tell origin ack-fail instead?

        // Update state and pay solver
        intents[guid].fulfilled = true;
        if (intent.token != address(0)) {
            // Pay ERC20 and native tip, if any
            IERC20(intent.token).safeTransfer(solverRecipient, intent.payment);
            if (intent.extraNativeTip > 0) {
                (bool success,) = payable(solverRecipient).call{ value: intent.extraNativeTip }("");
                if (!success) revert TransferFailed();
            }
        } else {
            // Pay native tokens
            (bool success,) = payable(solverRecipient).call{ value: intent.payment }("");
            if (!success) revert TransferFailed();
        }

        emit CompletedIntent(guid, solverRecipient);
        // Do we send ack-ok to the destination chain that payout was made to stop further attempts?
    }

    function cancelThing(bytes32 guid) external {
        // Pull state and validate caller is intent issuer and enough time has passed
        Intent memory intent = intents[guid];
        if (intent.from != msg.sender) revert Unauthorized();
        if (intent.timestamp > block.timestamp - cancelTimeout) revert CancelTimeout();

        // Issue refund
        if (intent.token != address(0)) {
            // Pay ERC20 and native tip, if any
            IERC20(intent.token).safeTransfer(msg.sender, intent.payment);
            if (intent.extraNativeTip > 0) {
                (bool success,) = payable(msg.sender).call{ value: intent.extraNativeTip }("");
                if (!success) revert TransferFailed();
            }
        } else {
            // Pay native tokens
            (bool success,) = payable(msg.sender).call{ value: intent.payment }("");
            if (!success) revert TransferFailed();
        }
    }
}
