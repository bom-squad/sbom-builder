package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/bom-squad/protobom/pkg/formats"
	"github.com/bom-squad/protobom/pkg/sbom"
	"github.com/bom-squad/protobom/pkg/writer"
	peparser "github.com/saferwall/pe"
	"github.com/sassoftware/relic/lib/authenticode"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Import struct {
	Dll      string   `json:"dll,omitempty"`
	Names    []string `json:"names,omitempty"`
	IsSystem bool     `json:"issystem,omitempty"`
}

type Export struct {
	Name string `json:"name,omitempty"`
}

type SigInfo struct {
	Subject   string `json:"subject,omitempty"`
	Issuer    string `json:"issuer,omitempty"`
	Serial    string `json:"serial,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
}

type HashInfo struct {
	Sha256 string `json:"sha256,omitempty"`
	Sha1   string `json:"sha1,omitempty"`
	Md5    string `json:"md5,omitempty"`
}

type PeInfo struct {
	Imports []Import `json:"imports,omitempty"`
	SigInfo *SigInfo `json:"sig_info,omitempty"`
}

type AssemblyInfo struct {
	Name           string
	MajorVersion   uint16
	MinorVersion   uint16
	BuildNumber    uint16
	RevisionNumber uint16
}

type CLRInfo struct {
	Module      string
	ModuleRefs  []string
	Assembly    AssemblyInfo
	AssemblyRef []AssemblyInfo
}

type FileInfo struct {
	Name        string   `json:"name,omitempty"`
	Size        int      `json:"size"`
	HashInfo    HashInfo `json:"hashinfo,omitempty"`
	IsPE        bool     `json:"ispe"`
	HasExport   bool     `json:"hasexport"`
	HasCLR      bool     `json:"hasclr"`
	PeInfo      *PeInfo  `json:"pe_info,omitempty"`
	VersionInfo map[string]string
	CLRInfo     CLRInfo
}

type File struct {
	FilesInfo map[string]FileInfo `json:"files_info,omitempty"`
}

var (
	outputfile      = flag.String("o", "", "result output filename (default: stdout)")
	maxWorkers      = flag.Int("w", 10, "max # of concurrent workers")
	recursive       = flag.Bool("r", true, "Walk directories recursively")
	softwarename    = flag.String("n", "software name", "software name")
	analyst         = flag.String("a", "analyst name", "name of analyst")
	format          = flag.String("f", "cyclonedx", "sbom format (cyclonedx or spdx)")
	softwareversion = flag.String("v", "v1.0", "software version")
)

func quickMzCheck(rd io.Reader) bool {
	var mz [2]byte
	_, err := io.ReadFull(rd, mz[:])
	if err != nil {
		return false
	}
	if mz[0] != 'M' && mz[1] != 'Z' {
		return false
	}
	return true
}

func getHashInfo(rd io.Reader, hinfo *HashInfo) {
	br := bufio.NewReader(rd)
	hSha256 := sha256.New()
	hSha1 := sha1.New()
	hMd5 := md5.New()
	mw := io.MultiWriter(hSha256, hMd5)
	io.Copy(mw, br)
	hinfo.Md5 = hex.EncodeToString(hMd5.Sum(nil))
	hinfo.Sha1 = hex.EncodeToString(hSha1.Sum(nil))
	hinfo.Sha256 = hex.EncodeToString(hSha256.Sum(nil))
}

// the concurrent pipeline code is slightly modified from https://go.dev/blog/pipelines
// we are using the bounded version

// walkFiles starts a goroutine to walk the directory tree at root and send the
// path of each regular file on the string channel.  It sends the result of the
// walk on the error channel.  If done is closed, walkFiles abandons its work.
func walkFiles(done <-chan struct{}, root string, recursive bool) (<-chan string, <-chan error) {
	paths := make(chan string)
	errc := make(chan error, 1)
	go func() {
		defer close(paths)
		errc <- filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			// If it's a directory and we're not in recursive mode, skip it.
			if info.IsDir() {
				if path == root {
					return nil
				}
				if !recursive {
					return filepath.SkipDir
				}
				return nil
			}
			// Ensure we only process regular files.
			if !info.Mode().IsRegular() {
				return nil
			}
			select {
			case paths <- path:
			case <-done:
				return errors.New("walk canceled")
			}
			return nil
		})
	}()
	return paths, errc
}

func processFile(f string) (FileInfo, error) {
	var inf FileInfo
	fh, err := os.Open(f)
	if err != nil {
		return inf, err
	}
	defer fh.Close()
	fstat, _ := fh.Stat()
	inf.Name = f
	inf.Size = int(fstat.Size())

	var hinfo HashInfo
	getHashInfo(fh, &hinfo)
	inf.HashInfo = hinfo

	fh.Seek(0, io.SeekStart)
	isPe := quickMzCheck(fh)
	if !isPe {
		return inf, nil
	}
	pe, err := peparser.New(f, &peparser.Options{})
	if err != nil {
		return inf, nil
	}
	err = pe.Parse()
	if err != nil {
		return inf, nil
	}
	inf.IsPE = isPe

	vinfo, err := pe.ParseVersionResources()
	if err != nil {
		return inf, err
	}
	inf.VersionInfo = vinfo

	peinfo := &PeInfo{}
	peinfo.Imports = make([]Import, len(pe.Imports))
	for i, imp := range pe.Imports {
		peinfo.Imports[i].Dll = imp.Name
		names := make([]string, len(imp.Functions))
		for i, fn := range imp.Functions {
			names[i] = fn.Name
		}
		peinfo.Imports[i].Names = names
	}
	inf.PeInfo = peinfo

	inf.HasExport = pe.FileInfo.HasExport

	if pe.HasCertificate {
		siginfo := &SigInfo{
			Issuer:  pe.Certificates.Info.Issuer,
			Subject: pe.Certificates.Info.Subject,
			Serial:  pe.Certificates.Info.SerialNumber,
		}
		sigs, _ := authenticode.VerifyPE(fh, true)
		if len(sigs) != 0 {
			siginfo.Timestamp = sigs[0].CounterSignature.SigningTime.String()
		}

		inf.PeInfo.SigInfo = siginfo
	}

	if pe.HasCLR {

		inf.HasCLR = true

		mod := pe.CLR.MetadataTables[peparser.Module].Content.([]peparser.ModuleTableRow)
		inf.CLRInfo.Module = string(pe.GetStringFromData(mod[0].Name, pe.CLR.MetadataStreams["#Strings"]))

		_, found := pe.CLR.MetadataTables[peparser.Assembly]
		if found {
			asm := pe.CLR.MetadataTables[peparser.Assembly].Content.([]peparser.AssemblyTableRow)
			inf.CLRInfo.Assembly.Name = string(pe.GetStringFromData(asm[0].Name, pe.CLR.MetadataStreams["#Strings"]))
			inf.CLRInfo.Assembly.MajorVersion = asm[0].MajorVersion
			inf.CLRInfo.Assembly.MinorVersion = asm[0].MinorVersion
			inf.CLRInfo.Assembly.RevisionNumber = asm[0].RevisionNumber
			inf.CLRInfo.Assembly.BuildNumber = asm[0].BuildNumber
		}

		_, found = pe.CLR.MetadataTables[peparser.AssemblyRef]
		if found {
			asmrefs := pe.CLR.MetadataTables[peparser.AssemblyRef].Content.([]peparser.AssemblyRefTableRow)
			inf.CLRInfo.AssemblyRef = make([]AssemblyInfo, len(asmrefs))
			for i, asmref := range asmrefs {
				inf.CLRInfo.AssemblyRef[i].Name = string(pe.GetStringFromData(asmref.Name, pe.CLR.MetadataStreams["#Strings"]))
				inf.CLRInfo.AssemblyRef[i].MajorVersion = asmref.MajorVersion
				inf.CLRInfo.AssemblyRef[i].MinorVersion = asmref.MinorVersion
				inf.CLRInfo.AssemblyRef[i].BuildNumber = asmref.BuildNumber
				inf.CLRInfo.AssemblyRef[i].RevisionNumber = asmref.RevisionNumber
			}
		}

		_, found = pe.CLR.MetadataTables[peparser.ModuleRef]
		if found {
			modrefs := pe.CLR.MetadataTables[peparser.ModuleRef].Content.([]peparser.ModuleRefTableRow)
			inf.CLRInfo.ModuleRefs = make([]string, len(modrefs))
			for i, modref := range modrefs {
				inf.CLRInfo.ModuleRefs[i] = string(pe.GetStringFromData(modref.Name, pe.CLR.MetadataStreams["#Strings"]))
			}
		}
	}

	return inf, nil
}

type result struct {
	file string
	info FileInfo
	err  error
}

func worker(done <-chan struct{}, paths <-chan string, c chan<- result) {
	for path := range paths {
		finfo, err := processFile(path)
		select {
		case c <- result{path, finfo, err}:
		case <-done:
			return
		}
	}
}

func processDir(dir string, recursive bool) (map[string]FileInfo, error) {
	done := make(chan struct{})
	defer close(done)

	dir = filepath.Clean(dir)
	paths, errc := walkFiles(done, dir, recursive)
	c := make(chan result)
	var wg sync.WaitGroup
	wg.Add(*maxWorkers)
	for i := 0; i < *maxWorkers; i++ {
		go func() {
			worker(done, paths, c)
			wg.Done()
		}()
	}
	go func() {
		wg.Wait()
		close(c)
	}()

	m := make(map[string]FileInfo)
	for r := range c {
		if r.err != nil {
			return nil, r.err
		}
		m[r.file] = r.info
	}

	if err := <-errc; err != nil {
		return nil, err
	}
	return m, nil
}

func main() {
	flag.Usage = func() {
		fmt.Printf("Usage: %s [flags] file/directory\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if len(flag.Args()) == 0 {
		flag.Usage()
		return
	}
	outf := os.Stdout
	var err error
	if *outputfile != "" {
		outf, err = os.OpenFile(*outputfile, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal(err)
		}
	}
	defer outf.Close()

	// var softwarename = flag.String("s", "software name", "name of software")

	document := sbom.NewDocument()
	document.Metadata.Authors = append(document.Metadata.Authors,
		&sbom.Person{Name: *analyst})
	document.Metadata.Tools = append(document.Metadata.Tools,
		&sbom.Tool{Name: "Veramine SBOM", Version: "0.2.0", Vendor: "Veramine, Inc"})

	metadata_node := &sbom.Node{
		Id:             fmt.Sprintf("%v@%v", sanitize(*softwarename), sanitize(*softwareversion)),
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_APPLICATION},
		Name:           *softwarename,
	}

	document.NodeList.AddNode(metadata_node)
	document.NodeList.RootElements = append(document.NodeList.RootElements, metadata_node.Id)

	m := make(map[string]FileInfo)
	for _, arg := range flag.Args() {
		finfo, err := os.Stat(arg)
		if err != nil {
			fmt.Println(err)
			continue
		}
		if finfo.Mode().IsRegular() {
			inf, _ := processFile(arg)
			m[arg] = inf
		}
		if finfo.Mode().IsDir() {
			tm := make(map[string]FileInfo)
			tm, _ = processDir(arg, *recursive)
			maps.Copy(m, tm)
		}
	}

	assembly_name_to_id_map := make(map[string]string)
	dll_to_id_map := make(map[string]string)

	for filename, fileinfo := range m {

		node := &sbom.Node{
			Id:       filepath.Base(filename), // this is default but is changed lower
			Name:     filepath.Base(filename),
			FileName: filename,
		}

		switch strings.ToLower(filepath.Ext(node.Name)) {
		case ".dll", ".sys":
			node.PrimaryPurpose = []sbom.Purpose{sbom.Purpose_LIBRARY}
		case ".exe":
			node.PrimaryPurpose = []sbom.Purpose{sbom.Purpose_APPLICATION}
		default:
			node.PrimaryPurpose = []sbom.Purpose{sbom.Purpose_FILE}
		}

		hashes := make(map[int32]string)
		hashes[int32(sbom.HashAlgorithm_MD5)] = fileinfo.HashInfo.Md5
		hashes[int32(sbom.HashAlgorithm_SHA1)] = fileinfo.HashInfo.Sha1
		hashes[int32(sbom.HashAlgorithm_SHA256)] = fileinfo.HashInfo.Sha256
		node.Hashes = hashes

		if len(fileinfo.VersionInfo) > 0 {

			fileversion, found := fileinfo.VersionInfo["FileVersion"]
			if found {
				node.Version = fileversion
			}
			copyright, found := fileinfo.VersionInfo["LegalCopyright"]
			if found {
				if copyright != "" && copyright != " " {
					node.Copyright = copyright
				}
			}
			description, found := fileinfo.VersionInfo["FileDescription"]
			if found {
				node.Description = description
			}
			internalname, found := fileinfo.VersionInfo["InternalName"]
			if found {
				node.Summary = internalname
			}
			originalfilename, found := fileinfo.VersionInfo["OriginalFilename"]
			if found {
				// if originalfilename, use that for summary.  If not, use internal name.  If neither, leave summary blank
				node.Summary = originalfilename
			}
			companyname, found := fileinfo.VersionInfo["CompanyName"]
			if found && len(companyname) > 0 {
				node.Suppliers = append(node.Suppliers,
					&sbom.Person{Name: companyname, IsOrg: true})
			}

		}

		if fileinfo.PeInfo != nil && fileinfo.PeInfo.SigInfo != nil {
			if len(node.Suppliers) == 0 {
				// didn't get CompanyName from PE header, use authenticode signature subject instead
				// fmt.Printf("Using SIGINFO instead of CompanyName %+v\n", fileinfo.PeInfo.SigInfo)
				node.Suppliers = append(node.Suppliers,
					&sbom.Person{Name: fileinfo.PeInfo.SigInfo.Subject, IsOrg: true})
			}

			if len(fileinfo.PeInfo.SigInfo.Timestamp) > 0 {
				// fmt.Printf("FOUND TIMESTAMP for [%v]: %v\n", filename, fileinfo.PeInfo.SigInfo.Timestamp)
				build_date, err := time.Parse("2006-01-02 15:04:05 -0700 MST", fileinfo.PeInfo.SigInfo.Timestamp)
				if err != nil {
					fmt.Printf("Error parsing time [%v], err %v\n", fileinfo.PeInfo.SigInfo.Timestamp, err)
				} else {
					node.BuildDate = timestamppb.New(build_date)
				}
			}
		}

		if len(node.Suppliers) == 0 {
			// there was no CompanyName in the PE header
			//  and also the file was not signed so we couldn't get supplier from digital signature
			// (not ideal)
			//  so instead we are going to try using the ProductName as last resort for supplier

			productname, found := fileinfo.VersionInfo["ProductName"]
			if found && len(productname) > 0 {
				node.Suppliers = append(node.Suppliers,
					&sbom.Person{Name: productname, IsOrg: true})
			}
		}

		if *format == "spdx" {
			node.Id = fmt.Sprintf("SPDXRef-File--%v-%v", sanitize(node.Name), strings.ToUpper(fileinfo.HashInfo.Sha256))
		} else if *format == "cyclonedx" {
			if len(node.Version) > 0 {
				node.Id = fmt.Sprintf("%v@%v", sanitize(node.Name), sanitize(node.Version))
			} else {
				node.Id = fmt.Sprintf("%v-%v", sanitize(node.Name), strings.ToUpper(fileinfo.HashInfo.Sha256))
			}
		} else {
			log.Fatal("unknown format type: %v\n", *format)
		}

		if fileinfo.HasExport {
			// fmt.Printf("importeddll_name_to_id_map[%v] = %v\n", strings.ToLower(node.Name), node.Id)
			dll_to_id_map[strings.ToLower(node.Name)] = node.Id
		}

		switch strings.ToUpper(filepath.Base(filename)) {
		case "LICENSE", "LICENCE", "LICENSE.TXT", "LICENCE.TXT":

			content, err := ioutil.ReadFile(filename)
			if err != nil {
				fmt.Printf("Error reading LICENSE file (%v) @ [%v]: %v\n", filepath.Base(filename), filename, err)
				continue
			}

			node.Licenses = append(node.Licenses, string(content))
		}

		if fileinfo.HasCLR {

			var should_deobfuscate bool
			if fileinfo.CLRInfo.Assembly.Name == "" {
				should_deobfuscate = true
				fmt.Printf("De-obfuscating [%v] (No Assembly.Name)..\n", filename)
			} else {
				// We did get an Assembly Name but is it busted?
				//  Check how many characters the assembly name has in common with the dll name
				//  if every single character is wrong, try to de-obfuscate it
				//   example: DLL cloudstoragepickerpaneui.dll Assembly.Name urrentfolderavailable
				//       ^^ that's busted
				// however, do not require EVERY character to be the same as dll name
				//   example: DLL sbkup64.exe Assembly.Name sbkupstub
				//        ^^ that is not busted, despite levenshtein distance of 6

				min_distance_to_check := minint(len(fileinfo.CLRInfo.Assembly.Name), len(node.Name))
				levenshtein_distance := levenshtein_distance(strings.ToLower(fileinfo.CLRInfo.Assembly.Name), strings.ToLower(node.Name))

				/*fmt.Printf("levenshtein_distance [%v] [%v] = %v\n",
				strings.ToLower(fileinfo.CLRInfo.Assembly.Name),
				strings.ToLower(node.Name),
				levenshtein_distance)*/

				if levenshtein_distance >= min_distance_to_check {
					// all/most chars are different
					should_deobfuscate = true
					fmt.Printf("De-obfuscating [%v] (Assembly.Name diff from DLL by %v chars)..\n", filename, levenshtein_distance)

				}

			}

			if should_deobfuscate {

				// if we didnt get an assmebly name, try to deobufscate and try again

				cmd := exec.Command("mono", "de4dot.exe", filename, "-o", "clean.dat")
				_, err := cmd.CombinedOutput()
				if err != nil {
					fmt.Println("de4dot Error:", err)
				} else {
					// fmt.Println(string(output))

					// fmt.Printf("Running processFile on clean.dat")
					inf, err := processFile("clean.dat")
					if err != nil {
						fmt.Printf("Error processFile clean.dat %v\n", err)
					} else {
						m[filename] = inf
						fileinfo = inf
					}
				}
			}

			if fileinfo.CLRInfo.Assembly.Name != "" {
				// fmt.Printf("ASSEMBLY NAME: [%v] NODE ID [%v]\n", fileinfo.CLRInfo.Assembly.Name, node.Id)
				assembly_name_to_id_map[strings.ToLower(fileinfo.CLRInfo.Assembly.Name)] = node.Id
			} else if fileinfo.HasCLR {
				// no assembly name but HasCLR
				//  common scenario when .NET binary is obfuscated
				// Ideally, should attempt to de-obfuscate the binary here
				//  in meantime, assume that Assembly.Name = filename without .dll on end
				if strings.HasSuffix(strings.ToLower(node.Name), ".dll") {
					fake_assembly_name := strings.ToLower(node.Name[:len(node.Name)-4])
					assembly_name_to_id_map[fake_assembly_name] = node.Id
					fmt.Printf("***MISSING Assembly.Name so using fake_assembly_name [%v] = %v\n", fake_assembly_name, node.Id)
				}
			}
			if fileinfo.CLRInfo.Module != "" {
				dll_to_id_map[strings.ToLower(fileinfo.CLRInfo.Module)] = node.Id
			}
		}

		document.NodeList.AddNode(node)
	}

	for _, node := range document.GetNodeList().GetNodes() {

		fileinfo, found := m[node.FileName]
		if !found {
			// fmt.Printf("NO FILEINFO FOR NODE ID [%v]\n", node.Id)
			continue
		}

		edge := &sbom.Edge{
			From: node.Id,
			Type: sbom.Edge_dependsOn,
		}

		contains := &sbom.Edge{
			From: metadata_node.Id,
			Type: sbom.Edge_contains,
		}

		for _, ref := range fileinfo.CLRInfo.AssemblyRef {

			if ref.Name == "" {
				continue
			}

			node_id, found := assembly_name_to_id_map[strings.ToLower(ref.Name)]
			if found {
				// this assembly is present in the package, add edge for that
				// fmt.Printf("#%v: NODE [%v] depends on [%v] (%v)\n", index+1, node.Name, ref.Name, node_id)
				edge.To = append(edge.To, node_id)
			} else {
				// this assmebly is not present in the package but we still want to represent the dependency
				//  Add a node to the node list with just the filename and then add an edge pointing to that new node

				fmt.Printf("Adding External node for [%v] (AssemblyRef)..\n", ref.Name)
				// fmt.Printf("#%v: NODE [%v] depends on AssemblyRef [%v] but cant find node_id in map. Adding it..\n", index+1, node.Id, ref.Name)

				externalnode := &sbom.Node{
					Id:             ref.Name,
					Name:           ref.Name,
					PrimaryPurpose: []sbom.Purpose{sbom.Purpose_FILE},
					Description:    "File not present in analyzed package.",
				}
				document.NodeList.AddNode(externalnode)

				assembly_name_to_id_map[strings.ToLower(ref.Name)] = externalnode.Id
				edge.To = append(edge.To, externalnode.Id)
				// contains.To = append(contains.To, externalnode.Id)
			}
		}

		for _, ref := range fileinfo.CLRInfo.ModuleRefs {

			if ref == "" {
				continue
			}

			node_id, found := dll_to_id_map[strings.ToLower(ref)]
			if found {
				// this assembly is present in the package, add edge for that
				edge.To = append(edge.To, node_id)
			} else {

				// try again by appending .dll to the ref.
				try_again_ref_name := fmt.Sprintf("%v.dll", strings.ToLower(ref))
				node_id, found = dll_to_id_map[try_again_ref_name]
				if found {
					// this assembly is present in the package, add edge for that
					edge.To = append(edge.To, node_id)
				} else {

					// this assmebly is not present in the package but we still want to represent the dependency
					//  Add a node to the node list with just the filename and then add an edge pointing to that new node

					// fmt.Printf("#%v: NODE [%v] depends on ModuleRef [%v] but cant find node_id in map. Adding it..\n", index+1, node.Id, strings.ToLower(ref))
					fmt.Printf("Adding External node for [%v] (ModuleRef)..\n", ref)

					externalnode := &sbom.Node{
						Id:             ref,
						Name:           ref,
						PrimaryPurpose: []sbom.Purpose{sbom.Purpose_FILE},
						Description:    "File not present in analyzed package.",
					}
					document.NodeList.AddNode(externalnode)

					dll_to_id_map[strings.ToLower(ref)] = externalnode.Id
					edge.To = append(edge.To, externalnode.Id)
					// contains.To = append(contains.To, externalnode.Id)

				}
			}
		}

		if fileinfo.PeInfo != nil {
			for _, importstruct := range fileinfo.PeInfo.Imports {

				node_id, found := dll_to_id_map[strings.ToLower(importstruct.Dll)]
				if found {
					// this assembly is present in the package, add edge for that
					edge.To = append(edge.To, node_id)
				} else {
					// this assmebly is not present in the package but we still want to represent the dependency
					//  Add a node to the node list with just the filename and then add an edge pointing to that new node

					fmt.Printf("Adding External node for [%v] (Import)..\n", importstruct.Dll)
					// fmt.Printf("#%v: NODE [%v] imports PeInfo Import [%v] but cant find node_id in map. Adding it..\n", index+1, node.Id, importstruct.Dll)

					externalnode := &sbom.Node{
						Id:             importstruct.Dll,
						Name:           importstruct.Dll,
						PrimaryPurpose: []sbom.Purpose{sbom.Purpose_FILE},
						Description:    "File not present in analyzed package. (Most likely a Microsoft binary.)",
					}
					document.NodeList.AddNode(externalnode)

					dll_to_id_map[strings.ToLower(importstruct.Dll)] = externalnode.Id
					edge.To = append(edge.To, externalnode.Id)
					// contains.To = append(contains.To, externalnode.Id)
				}
			}
		}

		if len(edge.To) > 0 {
			document.NodeList.AddEdge(edge)
		}
		if len(contains.To) > 0 {
			document.NodeList.AddEdge(contains)
		}

		// fmt.Printf("#%v: ASSEMBLYREFS: %+v\n", index+1, fileinfo.CLRInfo.AssemblyRef)

	}

	w := writer.New()

	// Write the SBOM to STDOUT in SPDX 2.3:
	w.WriteStreamWithOptions(
		document, os.Stdout, &writer.Options{Format: formats.SPDX23JSON},
	)

	// Write the SBOM to STDOUT in CycloneDX 1.4:
	w.WriteStreamWithOptions(
		document, os.Stdout, &writer.Options{Format: formats.CDX14JSON},
	)
}

func sanitize(input string) string {
	// Replace all whitespace characters with a dash
	whitespace := regexp.MustCompile(`\s`)
	input = whitespace.ReplaceAllString(input, "-")

	// Define a regular expression to match only alphanumeric characters, dashes, and underscores
	re := regexp.MustCompile(`[^a-zA-Z0-9-_.,-]+`)
	// Replace all non-matching characters with an empty string
	sanitized := re.ReplaceAllString(input, "")
	return sanitized
}

const minLengthThreshold = 32

// copied from https://github.com/agnivade/levenshtein/blob/master/levenshtein.go
func levenshtein_distance(a, b string) int {
	if len(a) == 0 {
		return utf8.RuneCountInString(b)
	}
	if len(b) == 0 {
		return utf8.RuneCountInString(a)
	}
	if a == b {
		return 0
	}

	// We need to convert to []rune if the strings are non-ASCII.
	// This could be avoided by using utf8.RuneCountInString
	// and then doing some juggling with rune indices,
	// but leads to far more bounds checks. It is a reasonable trade-off.
	s1 := []rune(a)
	s2 := []rune(b)

	// swap to save some memory O(min(a,b)) instead of O(a)
	if len(s1) > len(s2) {
		s1, s2 = s2, s1
	}
	lenS1 := len(s1)
	lenS2 := len(s2)

	// Init the row.
	var x []uint16
	if lenS1+1 > minLengthThreshold {
		x = make([]uint16, lenS1+1)
	} else {
		// We make a small optimization here for small strings.
		// Because a slice of constant length is effectively an array,
		// it does not allocate. So we can re-slice it to the right length
		// as long as it is below a desired threshold.
		x = make([]uint16, minLengthThreshold)
		x = x[:lenS1+1]
	}

	// we start from 1 because index 0 is already 0.
	for i := 1; i < len(x); i++ {
		x[i] = uint16(i)
	}

	// make a dummy bounds check to prevent the 2 bounds check down below.
	// The one inside the loop is particularly costly.
	_ = x[lenS1]
	// fill in the rest
	for i := 1; i <= lenS2; i++ {
		prev := uint16(i)
		for j := 1; j <= lenS1; j++ {
			current := x[j-1] // match
			if s2[i-1] != s1[j-1] {
				current = min(min(x[j-1]+1, prev+1), x[j]+1)
			}
			x[j-1] = prev
			prev = current
		}
		x[lenS1] = prev
	}
	return int(x[lenS1])
}

func min(a, b uint16) uint16 {
	if a < b {
		return a
	}
	return b
}

func minint(a, b int) int {
	if a < b {
		return a
	}
	return b
}
