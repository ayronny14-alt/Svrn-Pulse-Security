import { PulseError, PulseErrorCode } from '../src/errors.js';

describe('PulseError', () => {
    test('creates error with code and message', () => {
        const err = new PulseError(
            PulseErrorCode.INVALID_PAYLOAD_STRUCTURE,
            'Missing required field',
            { field: 'nonce' }
        );

        expect(err.name).toBe('PulseError');
        expect(err.code).toBe('INVALID_PAYLOAD_STRUCTURE');
        expect(err.message).toBe('Missing required field');
        expect(err.meta.field).toBe('nonce');
    });

    test('serializes to JSON', () => {
        const err = new PulseError(PulseErrorCode.PROOF_EXPIRED, 'Proof too old');
        const json = err.toJSON();
        expect(json.code).toBe('PROOF_EXPIRED');
        expect(json.message).toBe('Proof too old');
        expect(json.ts).toBeGreaterThan(0);
    });
});
