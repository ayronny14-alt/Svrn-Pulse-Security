import { mean, variance, stdDev, cv, median, percentile } from '../src/utils/stats.js';

describe('Stats Utilities', () => {
    test('computes mean correctly', () => {
        expect(mean([1, 2, 3, 4, 5])).toBe(3);
        expect(mean([])).toBe(0);
    });

    test('computes variance and stdDev', () => {
        const data = [10, 12, 23, 23, 16, 23, 21, 16];
        expect(variance(data)).toBeCloseTo(27.4286, 4);
        expect(stdDev(data)).toBeCloseTo(5.2372, 4);
    });

    test('computes coefficient of variation', () => {
        const data = [10, 10, 10];
        expect(cv(data)).toBe(0);
        expect(cv([1, 2, 3])).toBeCloseTo(0.5, 3);
    });

    test('computes median', () => {
        expect(median([1, 3, 2])).toBe(2);
        expect(median([1, 2, 3, 4])).toBe(2.5);
    });

    test('computes percentile', () => {
        const data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        expect(percentile(data, 50)).toBeCloseTo(5.5, 3);
        expect(percentile(data, 95)).toBeCloseTo(9.55, 3);
    });
});
