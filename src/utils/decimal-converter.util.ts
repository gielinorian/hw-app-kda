export const convertDecimal = (decimal: number | string): string => {
  if (typeof decimal === 'number') {
    if (decimal / Math.floor(decimal) === 1) {
      return decimal + '.0';
    }
  } else {
    if (decimal.includes('.')) {
      return decimal;
    }
  }
  return decimal as string;
};
