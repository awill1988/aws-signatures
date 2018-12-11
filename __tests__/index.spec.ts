import 'jest';
jest.setTimeout(10000);

describe('Helper Tests', () => {
  test('responds', () => {
    expect(1).toBe(1);
  });
});
