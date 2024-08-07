/// <reference path="../.astro/types.d.ts" />
/// <reference types="astro/client" />
import type { TypedPocketBase } from '@data/pocketbase-types'

declare global {
  namespace App {
    interface Locals extends Record<string, any> {
      pb: TypedPocketBase
    }
  }
}
