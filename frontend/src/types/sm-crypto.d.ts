declare module 'sm-crypto' {
  export function sm3(input: string | Uint8Array): string
  export const sm2: Record<string, unknown>
  export const sm4: {
    encrypt(input: string | Uint8Array, key: string): string
    decrypt(input: string | Uint8Array, key: string): string
  }
}
