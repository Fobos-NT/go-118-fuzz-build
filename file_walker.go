package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/packages"
)

var (
	customTestingName = "customFuzzTestingPkg"

	buildFlags2 = []string{
		"-buildmode", "c-archive",
		"-trimpath",
		"-gcflags", "all=-d=libfuzzer",
	}
	fuzzGoContents = `package testing

import (
	"fmt"
	"flag"
	"os"
	"reflect"
	"encoding/binary"
	"io"
	"math"
	"time"
)

var ProtoUnmarshal func(data []byte, msg any) error

type F struct {
	s *Source
	TempDirs []string
}

func NewF(data []byte) *F {
	return &F{s: NewSource(data), TempDirs: make([]string, 0)}
}

func (f *F) CleanupTempDirs() {
	for _, tempDir := range f.TempDirs {
		os.RemoveAll(tempDir)
	}
}

func (f *F) Add(args ...any)                   {}
func (c *F) Cleanup(f func())                  {}
func (c *F) Error(args ...any)                 {}
func (c *F) Errorf(format string, args ...any) {}
func (f *F) Fail()                             {}
func (c *F) FailNow()                          {}
func (c *F) Failed() bool                      { return false }
func (c *F) Fatal(args ...any)                 {}
func (c *F) Fatalf(format string, args ...any) {}
func (f *F) Fuzz(ff any) {
	dir, err := os.MkdirTemp("", "fuzzingTmpDir")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	t := &T{tempDirsParentDir: dir}
	refVal := reflect.ValueOf(t)

	f.s.FillAndCall(ff, refVal)
}
func (f *F) Helper() {}
func (c *F) Log(args ...any) {
	fmt.Print(args...)
}
func (c *F) Logf(format string, args ...any) {
	fmt.Println(fmt.Sprintf(format, args...))
}
func (c *F) Name() string             { return "libFuzzer" }
func (c *F) Setenv(key, value string) {}
func (c *F) Skip(args ...any) {
	panic("GO-FUZZ-BUILD-PANIC")
}
func (c *F) SkipNow() {
	panic("GO-FUZZ-BUILD-PANIC")
}
func (c *F) Skipf(format string, args ...any) {
	panic("GO-FUZZ-BUILD-PANIC")
}
func (f *F) Skipped() bool { return false }

func (f *F) TempDir() string {
	dir, err := os.MkdirTemp("", "fuzzdir-")
	if err != nil {
		panic(err)
	}
	f.TempDirs = append(f.TempDirs, dir)

	return dir
}

// Source takes a byteslice, and arguments can be pulled from it.
type Source struct {
	s         []byte
	i         int64 // current reading index
	exhausted bool
}

func NewSource(data []byte) *Source {
	return &Source{data, 0, false}
}

// IsExhausted returns true if we tried to read more data than this source
// could deliver.
func (s *Source) IsExhausted() bool {
	return s.exhausted
}

// Len returns the number of bytes of the unread portion of the data.
func (s *Source) Len() int {
	if s.i >= int64(len(s.s)) {
		return 0
	}
	return int(int64(len(s.s)) - s.i)
}

// Used returns the number of bytes already consumed.
func (s *Source) Used() int {
	return int(s.i)
}

// Read implements the io.Reader interface.
func (s *Source) Read(b []byte) (n int, err error) {
	if s.i >= int64(len(s.s)) {
		n, err = 0, io.EOF
	} else {
		n = copy(b, s.s[s.i:])
		s.i += int64(n)
	}
	if n < len(b) {
		s.exhausted = true
	}
	return n, err
}

// getBytes returns a slice of size bytes, as a direct reference if possible.
func (s *Source) getBytes(size int) []byte {
	if end := int(s.i) + size; end < len(s.s) { // Fast-path, no-copy deliver
		pos := s.i
		s.i += int64(size)
		return s.s[pos:end]
	}
	// Slow path
	buf := make([]byte, size)
	s.Read(buf)
	return buf
}

// readInt reads a signed integer from the source
func (s *Source) readInt(num reflect.Kind) int64 {
	switch num {
	case reflect.Int8:
		return int64(int8(s.getBytes(1)[0]))
	case reflect.Int16:
		return int64(int16(binary.BigEndian.Uint16(s.getBytes(2))))
	case reflect.Int32:
		return int64(int32(binary.BigEndian.Uint32(s.getBytes(4))))
	case reflect.Int64, reflect.Int:
		return int64(binary.BigEndian.Uint64(s.getBytes(8)))
	}
	panic(fmt.Sprintf("unsupported type: %v", num))
}

// readUint reads an unsigned integer from the source
func (s *Source) readUint(num reflect.Kind) uint64 {
	switch num {
	case reflect.Uint8:
		return uint64(uint8(s.getBytes(1)[0]))
	case reflect.Uint16:
		return uint64(binary.BigEndian.Uint16(s.getBytes(2)))
	case reflect.Uint32:
		return uint64(binary.BigEndian.Uint32(s.getBytes(4)))
	case reflect.Uint, reflect.Uint64:
		return binary.BigEndian.Uint64(s.getBytes(8))
	}
	panic(fmt.Sprintf("unsupported type: %v", num))
}

// FillAndCall fills the argument for the given ff (which is supposed to be a function),
// and then invokes the function.
// It returns 'true' if the function was invoked. A return-value of false means
// that the method was not invoked: probably because of insufficient input.
func (s *Source) FillAndCall(ff any, arg0 reflect.Value) (ok bool) {
	fn := reflect.ValueOf(ff)
	method := fn.Type()
	if method.Kind() != reflect.Func {
		panic(fmt.Sprintf("wrong type: %T", ff))
	}
	args := make([]reflect.Value, method.NumIn())
	args[0] = arg0
	if method.NumIn() == 2 && isProtoMessage(method.In(1)) {
		args[1] = s.fillArg(method.In(1), s.Len())
		fn.Call(args)
		return true
	}
	var dynamic []int
	// Fill all fixed-size arguments first, then dynamic-sized fields.
	for i := 1; i < method.NumIn(); i++ {
		v := method.In(i)
		if v.Kind() <= reflect.Float64 { // fixed-size
			args[i] = s.fillArg(v, 0)
		} else { // dynamic or panic later
			dynamic = append(dynamic, i)
		}
	}
	// Second loop to fill dynamic-sized stuff
	// For filling the dynamic fields.
	// If we have only one field, it should get all the remaining input.
	// If we have N, then,
	// 1. Read N bytes [b1, b2, b3 .. bn] .
	// 2. Let the relative weights of b determine how much of the
	//    remaining input that field n gets
	weights := s.getBytes(len(dynamic))
	sum := 0
	for _, v := range weights {
		sum += int(v)
	}
	bytesLeft := s.Len()
	for i, argNum := range dynamic {
		if i == len(dynamic)-1 { // last element, it get's all that if left
			args[argNum] = s.fillArg(method.In(argNum), s.Len())
			break
		}
		var argSize = bytesLeft / len(dynamic)
		if sum > 0 {
			argSize = (bytesLeft * int(weights[i])) / sum
		}
		args[argNum] = s.fillArg(method.In(argNum), argSize)
	}
	fn.Call(args)
	return true
}

func (s *Source) fillArg(v reflect.Type, max int) reflect.Value {
	newElem := reflect.New(v).Elem()
	switch k := v.Kind(); k {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		newElem.SetInt(s.readInt(k))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		newElem.SetUint(s.readUint(k))
	case reflect.Float32:
		newElem.Set(reflect.ValueOf(math.Float32frombits(uint32(s.readUint(reflect.Uint32)))))
	case reflect.Float64:
		newElem.Set(reflect.ValueOf(math.Float64frombits(s.readUint(reflect.Uint64))))
	case reflect.Bool:
		newElem.Set(reflect.ValueOf(s.readUint(reflect.Uint8)&0x1 != 0))
	case reflect.String:
		newElem.SetString(string(s.getBytes(max)))
	case reflect.Slice:
		if v.Elem().Kind() == reflect.Uint8 { // []byte
			newElem.SetBytes(s.getBytes(max))
		} else {
			panic(fmt.Sprintf("unsupported type: %T", newElem.Kind))
		}
	case reflect.Pointer:
		if !isProtoMessage(v) {
			panic(fmt.Sprintf("unsupported type: %T", newElem.Kind))
		}
		msg := reflect.New(v.Elem())
		if err := ProtoUnmarshal(s.getBytes(max), msg.Interface()); err != nil {
			panic("GO-FUZZ-BUILD-PANIC")
		}
		newElem.Set(msg)
	default:
		panic(fmt.Sprintf("unsupported type: %T", newElem.Kind))
	}
	return newElem
}

func isProtoMessage(v reflect.Type) bool {
	if ProtoUnmarshal == nil || v.Kind() != reflect.Pointer {
		return false
	}
	_, ok := v.MethodByName("ProtoReflect")
	return ok
}

// For compliance only below
type corpusEntry = struct {
	Parent     string
	Path       string
	Data       []byte
	Values     []any
	Generation int
	IsSeed     bool
}

type InternalFuzzTarget struct {
	Name string
	Fn   func(f *F)
}

func initFuzzFlags() {
	matchFuzz = flag.String("test.fuzz", "", "run the fuzz test matching regexp")
	flag.Var(&fuzzDuration, "test.fuzztime", "time to spend fuzzing; default is to run indefinitely")
	flag.Var(&minimizeDuration, "test.fuzzminimizetime", "time to spend minimizing a value after finding a failing input")

	fuzzCacheDir = flag.String("test.fuzzcachedir", "", "directory where interesting fuzzing inputs are stored (for use only by cmd/go)")
	isFuzzWorker = flag.Bool("test.fuzzworker", false, "coordinate with the parent process to fuzz random values (for use only by cmd/go)")
}

var (
	matchFuzz        *string
	fuzzDuration     durationOrCountFlag
	minimizeDuration = durationOrCountFlag{d: 60 * time.Second, allowZero: true}
	fuzzCacheDir     *string
	isFuzzWorker     *bool

	// corpusDir is the parent directory of the fuzz test's seed corpus within
	// the package.
	corpusDir = "testdata/fuzz"
)

func runFuzzTests(deps testDeps, fuzzTests []InternalFuzzTarget, deadline time.Time) (ran, ok bool) {
	return true, true
}

func runFuzzing(deps testDeps, fuzzTests []InternalFuzzTarget) (ok bool) {
	return true
}

const fuzzWorkerExitCode = 70
`

	ttSourceFile = `package testing

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

// T can be used to terminate the current fuzz iteration
// without terminating the whole fuzz run. To do so, simply
// panic with the text "GO-FUZZ-BUILD-PANIC" and the fuzzer
// will recover.
type T struct {
	TempDirs []string
}

func NewT() *T {
	tempDirs := make([]string, 0)
	return &T{TempDirs: tempDirs}
}

func unsupportedApi(name string) string {
	plsOpenIss := "Please open an issue https://github.com/AdamKorcz/go-118-fuzz-build if you need this feature."
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s is not supported when fuzzing in libFuzzer mode\n.", name))
	b.WriteString(plsOpenIss)
	return b.String()
}

func (t *T) Cleanup(f func()) {
	f()
}

func (t *T) Context() context.Context {
	return context.Background()
}

func (t *T) Deadline() (deadline time.Time, ok bool) {
	panic(unsupportedApi("t.Deadline()"))
}

func (t *T) Error(args ...any) {
	fmt.Println(args...)
	panic("error")
}

func (t *T) Errorf(format string, args ...any) {
	fmt.Printf(format+"\n", args...)
	panic("errorf")
}

func (t *T) Fail() {
	panic("Called T.Fail()")
}

func (t *T) FailNow() {
	panic("Called T.Fail()")
	panic(unsupportedApi("t.FailNow()"))
}

func (t *T) Failed() bool {
	panic(unsupportedApi("t.Failed()"))
}

func (t *T) Fatal(args ...any) {
	fmt.Println(args...)
	panic("fatal")
}
func (t *T) Fatalf(format string, args ...any) {
	fmt.Printf(format+"\n", args...)
	panic("fatal")
}
func (t *T) Helper() {
	// We can't support it, but it also just impacts how failures are reported, so we can ignore it
}
func (t *T) Log(args ...any) {
	fmt.Println(args...)
}

func (t *T) Logf(format string, args ...any) {
	fmt.Println(format)
	fmt.Println(args...)
}

func (t *T) Name() string {
	return "libFuzzer"
}

func (t *T) Parallel() {
	panic(unsupportedApi("t.Parallel()"))
}
func (t *T) Run(name string, f func(t *T)) bool {
	f(t)
	return true
}

func (t *T) Setenv(key, value string) {

}

func (t *T) Skip(args ...any) {
	panic("GO-FUZZ-BUILD-PANIC")
}
func (t *T) SkipNow() {
	panic("GO-FUZZ-BUILD-PANIC")
}

// Is not really supported. We just skip instead
// of printing any message. A log message can be
// added if need be.
func (t *T) Skipf(format string, args ...any) {
	panic("GO-FUZZ-BUILD-PANIC")
}
func (t *T) Skipped() bool {
	panic(unsupportedApi("t.Skipped()"))
}
func (t *T) TempDir() string {
	dir, err := os.MkdirTemp("", "fuzzdir-")
	if err != nil {
		panic(err)
	}
	t.TempDirs = append(t.TempDirs, dir)

	return dir
}

func (t *T) CleanupTempDirs() {
	if len(t.TempDirs) > 0 {
		for _, tempDir := range t.TempDirs {
			os.RemoveAll(tempDir)
		}
	}
}

`
)

type Overlay struct {
	Replace map[string]string
}

type FileWalker struct {
	renamedFiles     map[string]string
	renamedTestFiles map[string]string // key = old, correct name, value = temporary name
	rewrittenFiles   []string
	// Stores the original files
	originalFiles map[string]string
	tmpDir        string
	overlayMap    *Overlay
	sanitizer     string
	fuzzerPath    string
	goRootDir     string
	allFiles      []string
	overlayArgs   []string
	protoTarget   *ProtoTarget
	fuzzerPkgPath string
}

func NewFileWalker() *FileWalker {
	tmpDir, err := os.MkdirTemp("", "gofuzzbuild")
	if err != nil {
		panic(err)
	}
	goRootDir := getGoRootPath()
	return &FileWalker{
		renamedFiles:     make(map[string]string),
		renamedTestFiles: make(map[string]string),
		rewrittenFiles:   make([]string, 0),
		originalFiles:    make(map[string]string),
		tmpDir:           tmpDir,
		overlayMap:       &Overlay{Replace: make(map[string]string)},
		allFiles:         make([]string, 0),
		overlayArgs:      make([]string, 0),
		goRootDir:        goRootDir,
	}
}

func (walker *FileWalker) visibleFuzzerPath() string {
	return strings.TrimSuffix(strings.TrimSuffix(walker.fuzzerPath, ".go"), "_test") + "_libFuzzer.go"
}

// restoreFile stages the backup beside the destination so the final rename is
// atomic even when the backup and the checkout are on different filesystems.
func restoreFile(backup, destination string) error {
	contents, err := os.ReadFile(backup)
	if err != nil {
		return err
	}
	info, err := os.Stat(backup)
	if err != nil {
		return err
	}
	staged, err := os.CreateTemp(filepath.Dir(destination), ".gofuzzrestore-*")
	if err != nil {
		return err
	}
	defer os.Remove(staged.Name())
	defer staged.Close()
	if err := staged.Chmod(info.Mode().Perm()); err != nil {
		return err
	}
	if _, err := staged.Write(contents); err != nil {
		return err
	}
	if err := staged.Close(); err != nil {
		return err
	}
	return os.Rename(staged.Name(), destination)
}

func (walker *FileWalker) cleanUp() error {
	var restoreErrors []error
	for oldName, renamedTestFile := range walker.renamedTestFiles {
		if err := restoreFile(renamedTestFile, oldName); err != nil {
			restoreErrors = append(restoreErrors, fmt.Errorf("restore %s: %w", oldName, err))
		} else {
			delete(walker.renamedTestFiles, oldName)
		}
	}
	if len(restoreErrors) != 0 {
		// Do not delete the only remaining copies if restoration failed.
		return fmt.Errorf("cleanup failed; backups kept in %s: %w", walker.tmpDir, errors.Join(restoreErrors...))
	}
	if walker.fuzzerPath != "" {
		if err := os.Remove(walker.visibleFuzzerPath()); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	for _, path := range walker.rewrittenFiles {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return os.RemoveAll(walker.tmpDir)
}

func (walker *FileWalker) createRewrittenHarness(path string, fset1 *token.FileSet, parsedFile *ast.File) error {
	originalFuzzerContents, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	originalInfo, err := os.Stat(path)
	if err != nil {
		return err
	}
	originalFuzzerFileCopy, err := os.CreateTemp(walker.tmpDir, "")
	if err != nil {
		return err
	}
	defer originalFuzzerFileCopy.Close()
	if err := originalFuzzerFileCopy.Chmod(originalInfo.Mode().Perm()); err != nil {
		return err
	}
	_, err = originalFuzzerFileCopy.Write(originalFuzzerContents)
	if err != nil {
		return err
	}
	if err = originalFuzzerFileCopy.Close(); err != nil {
		return err
	}
	visibleFuzzerPath := walker.visibleFuzzerPath()
	fff, err := os.Create(visibleFuzzerPath)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	// Preserve original source positions in the coverage profile. Temporary
	// filenames disappear during cleanup, before the report reads the sources.
	config := printer.Config{Mode: printer.SourcePos, Tabwidth: 8}
	if err := config.Fprint(&buf, fset1, parsedFile); err != nil {
		return err
	}
	// SourcePos emits line-only directives, which make Go report column zero.
	// Retain columns as well so go tool cover can render the original source.
	lines := strings.Split(buf.String(), "\n")
	for index, line := range lines {
		if strings.HasPrefix(line, "//line ") {
			lines[index] = line + ":1"
		}
	}

	_, err = fff.WriteString(strings.Join(lines, "\n"))
	if err != nil {
		return err
	}
	if err = fff.Close(); err != nil {
		return err
	}

	walker.renamedTestFiles[walker.fuzzerPath] = originalFuzzerFileCopy.Name()
	err = os.Remove(path)
	if err != nil {
		return err
	}
	fmt.Println("created rewritten harness")
	return nil
}

// "path" is expected to be a file in a module
// that a fuzzer uses.
func (walker *FileWalker) RewriteFile(path, fuzzFuncName string) {
	if filepath.Ext(path) != ".go" {
		return
	}

	//fileName := filepath.Base(path)
	if strings.HasSuffix(path, "_test.go") {
		if filepath.Dir(path) != filepath.Dir(walker.fuzzerPath) {
			return
		}
	}

	fset1 := token.NewFileSet()
	parsedFile, err := parser.ParseFile(fset1, path, nil, 0)
	if err != nil {
		fmt.Println(err)
		return
	}

	// If coverage: prepend "F"
	if walker.sanitizer == "coverage" && strings.EqualFold(path, walker.fuzzerPath) {

		// Change fuzz function name from Fuzz* to FFuzz*
		for _, decl := range parsedFile.Decls {
			if _, ok := decl.(*ast.FuncDecl); ok {
				if decl.(*ast.FuncDecl).Name.Name == fuzzFuncName {
					decl.(*ast.FuncDecl).Name.Name = fmt.Sprintf("F%s", fuzzFuncName)
				}
			}
		}

		// Make a copy of the original fuzzer contents
		err = walker.createRewrittenHarness(path, fset1, parsedFile)
		if err != nil {
			panic(err)
		}
	} else if strings.HasSuffix(path, "_test.go") && filepath.Dir(path) == filepath.Dir(walker.fuzzerPath) {
		fmt.Println("renaming _test.go file in fuzzer dir: ", path)
		fileBytes, err := os.ReadFile(path)
		if err != nil {
			return
		}
		keyName := strings.TrimSuffix(path, "_test.go") + "_libFuzzer.go"
		if walker.sanitizer == "coverage" {
			// cmd/cover reads physical files, not virtual overlay additions.
			// Retain test helpers as regular code but hide the original test file
			// from go test so only the generated corpus runner gets registered.
			f, err := os.OpenFile(keyName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
			if err != nil {
				panic(err)
			}
			walker.rewrittenFiles = append(walker.rewrittenFiles, keyName)
			_, writeErr := fmt.Fprintf(f, "//line %s:1:1\n%s", path, fileBytes)
			closeErr := f.Close()
			if err := errors.Join(writeErr, closeErr); err != nil {
				panic(err)
			}
			walker.overlayMap.Replace[path] = ""
			return
		}
		f, err := os.CreateTemp(walker.tmpDir, "")
		if err != nil {
			panic(err)
		}

		_, err = f.Write(fileBytes)
		if err != nil {
			panic(err)
		}
		if err = f.Close(); err != nil {
			panic(err)
		}
		walker.overlayMap.Replace[keyName] = f.Name()
	}
}

// Gets the full path of the file in which the "func Fuzz" is
func (walker *FileWalker) getAbsPathOfFuzzFile(pkgPath, fuzzerName string, buildFlags []string) error {
	pkgs, err := packages.Load(&packages.Config{
		Mode:       LoadMode,
		BuildFlags: buildFlags,
		Tests:      true,
	}, "pattern="+pkgPath)
	if err != nil {
		return err
	}
	for _, pkg := range pkgs {
		if pkg.PkgPath != pkgPath {
			continue
		}
		for _, file := range pkg.GoFiles {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, file, nil, 0)
			if err != nil {
				return err
			}
			for _, decl := range f.Decls {
				if _, ok := decl.(*ast.FuncDecl); ok {
					if decl.(*ast.FuncDecl).Name.Name == fuzzerName {
						walker.fuzzerPath = file
						return nil

					}
				}
			}
		}
	}
	return fmt.Errorf("Could not find the fuzz func")
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func getGoRootPath() string {
	out, err := exec.Command("go", "env", "-json").Output()
	if err != nil {
		panic(err)
	}
	m := make(map[string]string)
	err = json.Unmarshal(out, &m)
	if err != nil {
		panic(err)
	}
	goRootDir := m["GOROOT"]
	return goRootDir
}

// Adds an overlay file to o.
func (o *Overlay) AddOverlayFile(path string) error {
	//newOverlayMap := &Overlay{Replace: make(map[string]string)}
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("Could not find overlay file %s", err.Error())
	}
	usersOverlayMap := &Overlay{}
	err = json.Unmarshal(b, usersOverlayMap)
	if err != nil {
		return fmt.Errorf("Could not read overlay file %s", err.Error())
	}

	for k, v := range usersOverlayMap.Replace {
		if _, ok := o.Replace[k]; ok {
			return fmt.Errorf("users overlay file overwrites existing files")
		}
		o.Replace[k] = v
	}
	return nil
}

func (walker *FileWalker) CreateStdLibFuzzGoFile() error {
	fuzzGoFile, err := os.CreateTemp(walker.tmpDir, "fuzz.go")
	if err != nil {
		return err
	}
	if _, err := fuzzGoFile.Write([]byte(fuzzGoContents)); err != nil {
		fuzzGoFile.Close()
		return err
	}
	fuzzGoFile.Close()
	walker.overlayMap.Replace[filepath.Join(walker.goRootDir, "src/testing/fuzz.go")] = fuzzGoFile.Name()
	return nil
}

func (walker *FileWalker) CreateStdLibTestingGoFile() error {
	testingGoFileBytes, err := os.ReadFile(filepath.Join(walker.goRootDir, "src/testing/testing.go"))
	if err != nil {
		return err
	}
	updatedTestingGoContents := placeHooks(string(testingGoFileBytes), walker.sanitizer == "coverage")
	testingGoFile, err := os.CreateTemp(walker.tmpDir, "testing.go")
	if err != nil {
		return err
	}
	if _, err := testingGoFile.Write([]byte(updatedTestingGoContents)); err != nil {
		testingGoFile.Close()
		return err
	}
	testingGoFile.Close()
	//fmt.Println(updatedTestingGoContents)

	walker.overlayMap.Replace[filepath.Join(walker.goRootDir, "src/testing/testing.go")] = testingGoFile.Name()
	return nil
}

func (walker *FileWalker) SaveOverlayMapToFile() error {
	overlayFile, err := os.CreateTemp(walker.tmpDir, "ossFuzzOverlayFile.json")
	if err != nil {
		return err
	}
	overlayJson, err := json.Marshal(walker.overlayMap)
	if err != nil {
		return err
	}
	if _, err := overlayFile.Write(overlayJson); err != nil {
		overlayFile.Close()
		return err
	}
	overlayFile.Close()
	walker.overlayArgs = append(walker.overlayArgs, "-overlay", overlayFile.Name())
	return nil
}

func (walker *FileWalker) CreateOverlayFile(usersOverlayFile string) error {
	if usersOverlayFile != "" {
		err := walker.overlayMap.AddOverlayFile(usersOverlayFile)
		if err != nil {
			return err
		}
	}

	err := walker.CreateStdLibFuzzGoFile()
	if err != nil {
		return err
	}

	err = walker.CreateStdLibTestingGoFile()
	if err != nil {
		return err
	}

	err = walker.SaveOverlayMapToFile()
	if err != nil {
		return err
	}
	
	return nil
}

// Returns the path to the coverage test and the temp file.
func (walker *FileWalker) createCoverageRunner(flagFunc, fuzzerPackageName string) error {
	modifiedFuncName := fmt.Sprintf("F%s", flagFunc)
	f, err := os.CreateTemp(walker.tmpDir, "coverageFile")
	if err != nil {
		return err
	}
	defer f.Close()
	data := &Data{
		Func:    modifiedFuncName,
		PkgName: fuzzerPackageName,
	}
	if walker.protoTarget != nil {
		walker.protoTarget.fillData(data, walker.fuzzerPkgPath, "")
	}
	err = coverageTmpl.Execute(f, data)
	if err != nil {
		return err
	}
	walker.overlayMap.Replace[filepath.Join(filepath.Dir(walker.fuzzerPath), "oss_fuzz_coverage_test.go")] = f.Name()
	return nil
}

func (walker *FileWalker) CreateAndModifyFiles(modulePath, fuzzerFuncName, flagOverlay, fuzzerPackage string) {
	if walker.sanitizer == "coverage" {
		if err := walker.createCoverageRunner(fuzzerFuncName, fuzzerPackage); err != nil {
			panic(err)
		}
	}
	fuzzerDir := filepath.Dir(walker.fuzzerPath)
	filesInFuzzerDir, err := os.ReadDir(fuzzerDir)
	if err != nil {
		panic(err)
	}

	for _, file := range filesInFuzzerDir {
		fi, err := os.Stat(filepath.Join(fuzzerDir, file.Name()))
		if err != nil {
			panic(err)
		}
		if !fi.Mode().IsRegular() {
			continue
		}
		walker.RewriteFile(filepath.Join(fuzzerDir, file.Name()), fuzzerFuncName)
	}
	err = walker.CreateOverlayFile(flagOverlay)
	if err != nil {
		panic(err)
	}

}

// takes the file contents og go/src/testing/testing.go
// and places the hooks and returns the updated file contents
func PlaceHooks(fileContents string) string {
	return placeHooks(fileContents, false)
}

func placeHooks(fileContents string, coverage bool) string {
	contentsCopy := fileContents
	for k, v := range hookMap {
		// The real test runner calls Failed even when the corpus replay passes.
		// Its normal implementation also works on the fuzzer's zero-value T.
		if coverage && k == "func (c *common) Failed() bool {" {
			continue
		}
		contentsCopy = strings.Replace(contentsCopy, k, v, 1)
	}
	contentsCopy += "\n"
	contentsCopy += `
func (t *T) TempDir() string {
	tmpFuzzDir, err := os.MkdirTemp(t.tempDirsParentDir, "fuzzdir-")
	if err != nil {
		panic(err)
	}
	return tmpFuzzDir
}`

	contentsCopy += `
func (f *F) Chdir(dir string) {
	panic("f.Chdir() is not implemented. Create an issue at github.com/AdamKorcz/go-118-fuzz-build if you need it")
}`

	contentsCopy += `
func (f *F) Context() context.Context {
	panic("f.Context() is not implemented. Create an issue at github.com/AdamKorcz/go-118-fuzz-build if you need it")
}`

	contentsCopy += `
func (f *F) private() {
}`

	return contentsCopy
}

var (
	hookMap = map[string]string{
		"func (c *common) Cleanup(f func()) {":                   "func (c *common) Cleanup(f func()) {\nf()",
		"func (c *common) Context() context.Context {":           "func (c *common) Context() context.Context {\nreturn context.Background()",
		"func (t *T) Deadline() (deadline time.Time, ok bool) {": "func (t *T) Deadline() (deadline time.Time, ok bool) {\npanic(\"t.Deadline()\")",
		"func (c *common) Error(args ...any) {":                  "func (c *common) Error(args ...any) {\nfmt.Println(args...)\npanic(\"error\")",
		"func (c *common) Errorf(format string, args ...any) {":  "func (c *common) Errorf(format string, args ...any) {\nfmt.Printf(format+\"\\n\", args...)\npanic(\"errorf\")",
		"func (c *common) Fail() {":                              "func (c *common) Fail() {\npanic(\"Called T.Fail()\")",
		"func (c *common) FailNow() {":                           "func (c *common) FailNow() {\npanic(\"t.FailNow()\")",
		"func (c *common) Failed() bool {":                       "func (c *common) Failed() bool {\npanic(\"t.Failed()\")",
		"func (c *common) Fatal(args ...any) {":                  "func (c *common) Fatal(args ...any) {\nfmt.Println(args...)\npanic(\"fatal\")",
		"func (c *common) Fatalf(format string, args ...any) {":  "func (c *common) Fatalf(format string, args ...any) {\nfmt.Printf(format+\"\\n\", args...)\npanic(\"fatal\")",
		"func (c *common) Helper() {":                            "func (c *common) Helper() {\nreturn",
		"func (c *common) Log(args ...any) {":                    "func (c *common) Log(args ...any) {\nfmt.Println(args...)\nreturn",
		"func (c *common) Logf(format string, args ...any) {":    "func (c *common) Logf(format string, args ...any) {\nfmt.Println(format)\nfmt.Println(args...)\nreturn",
		"func (c *common) Name() string {":                       "func (c *common) Name() string {\nreturn \"libFuzzer\"",
		"func (t *T) Parallel() {":                               "func (t *T) Parallel() {\npanic(\"t.Parallel()\")",
		"func (t *T) Run(name string, f func(t *T)) bool {":      "func (t *T) Run(name string, f func(t *T)) bool {\nf(t)\nreturn true",
		////////"func (c *common) Setenv(key, value string) {": "func (c *common) Setenv(key, value string) {\n"
		"func (c *common) Skip(args ...any) {":    "func (c *common) Skip(args ...any) {\npanic(\"GO-FUZZ-BUILD-PANIC\")",
		"func (c *common) SkipNow(args ...any) {": "func (c *common) SkipNow(args ...any) {\npanic(\"GO-FUZZ-BUILD-PANIC\")",
		"func (c *common) Skipf(args ...any) {":   "func (c *common) Skipf(args ...any) {\npanic(\"GO-FUZZ-BUILD-PANIC\")",
		"func (c *common) Skipped() bool {":       "func (c *common) Skipped() bool {\npanic(\"t.Skipped()\")",
		"type T struct {":                         "type T struct {\ntempDirsParentDir string",
		//"func (c *common) TempDir() string {": "func (c *common) TempDir() string {\ntmpFuzzDir, err := os.MkdirTemp(c.tempDirsParentDir, \"fuzzdir-\")\nif err != nil {\npanic(err)\n}\nreturn tmpFuzzDir",
	}
)
