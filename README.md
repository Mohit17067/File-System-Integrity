# File-System-Integrity
A secure library (SecureFS) on top of the existing file system interfaces that raises the alarm if the integrity of the
files created through the secure library APIs is compromised. At the high-level, SecureFS maintains a Merkle tree for every file to check the consistency of file blocks before every read and write. The root of the Merkle tree is saved on disk to verify the integrity of files after reboot.

## Integrity Check
To check the integrity of file, SecureFS computes a unique hash value from the
file contents and store in secure.txt file. SecureFS assumes that secure.txt
cannot be tampered. When a file is opened, SecureFS creates a Merkle tree
(in memory) from the file blocks. secure.txt contains the root of the Merkle
tree corresponding to every file created by the SecureFS interface. Whenever
a file is modified the Merkle tree is updated, and the root of the Merkle tree is
synced with the secure.txt. The in-memory Merkle tree is deleted when the
file is closed.

## Testing
Execute `make && make run` in the filesys folder to run the test cases.
The filesys folder contains four test cases.
