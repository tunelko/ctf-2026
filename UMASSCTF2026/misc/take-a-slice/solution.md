# Take a Slice — UMassCTF 2026 (MISC)

## TL;DR
Binary STL file of a LEGO Technic triangular piece. Flag is engraved on the diagonal (hypotenuse) face — visible in a 3D viewer.

## Analysis
- File `cake` has no extension but is a binary STL (80-byte null header + 39210 triangles)
- 3D model is a right-triangle LEGO Technic beam with stud pattern on top and pin holes along the sides
- "Take a Slice" / "It's in the name!" hints at slicing/viewing the 3D model

## Solution
1. Rename `cake` to `cake.stl`
2. Open in any STL viewer (FreeCAD, Windows 3D Viewer, viewstl.com)
3. Rotate to view the diagonal (hypotenuse) face
4. Read the engraved text

## Flag
```
UMASS{SL1C3_&_D1C3}
```
