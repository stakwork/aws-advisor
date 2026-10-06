export const cronOff = (expr: string) => !expr || /^(off|none|false|0)$/i.test(expr);
