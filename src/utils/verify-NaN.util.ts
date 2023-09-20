export const verifyNaN = (value?: string | number): boolean => {
  if (!value) return false;
  return isNaN(value as unknown as number);
};
