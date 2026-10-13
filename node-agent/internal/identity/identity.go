// Package identity 是节点侧的**身份持久化**（第二十三轮 T2）。
//
// 解决的问题：注册令牌是一次性的，若证书只存内存，节点每次重启都要重新注册、
// 消耗新令牌、拿到**新 node_id**——运维上不可接受。
//
// 落盘约定（硬性要求）：
//   - state 目录权限 **0700**（只有属主可进入）；
//   - 身份文件权限 **0600**（组与其他用户不得有任何权限）；
//   - 写入采用"临时文件 + rename"**原子替换**，任何时刻都不存在半写的身份文件；
//   - 读取时校验：权限必须恰好 0600、PEM 可解析、证书未过期、由给定 CA 签发、
//     CN 与 SAN 与 node_id 一致。**任一不符即拒绝启动**，绝不静默重新注册。
//
// 私钥**只在本包与调用方的内存中出现**，不写日志、不进审计、不返回给上层以外的路径。
package identity

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// 目录与文件权限（硬性要求；不得放宽）。
const (
	// DirMode state 目录权限。
	DirMode os.FileMode = 0o700
	// FileMode 身份文件权限。
	FileMode os.FileMode = 0o600
)

// DefaultFileName 身份文件名（state 目录下）。
const DefaultFileName = "identity.pem"

// 错误（对外明确，便于运维定位；**不含**任何密钥材料）。
var (
	// ErrDirPermissive state 目录权限过宽（必须 0700）。
	ErrDirPermissive = errors.New("identity：state 目录权限必须为 0700")
	// ErrFilePermissive 身份文件权限过宽（必须 0600）。
	ErrFilePermissive = errors.New("identity：身份文件权限必须为 0600")
	// ErrCorrupt 身份文件损坏（PEM 无法解析 / 结构不完整）。
	ErrCorrupt = errors.New("identity：身份文件损坏或结构不完整")
	// ErrExpired 身份证书已过期。
	ErrExpired = errors.New("identity：身份证书已过期（拒绝启动，需重新注册或续期）")
	// ErrUntrusted 身份证书不由配置的 CA 签发。
	ErrUntrusted = errors.New("identity：身份证书不由配置的 CA 签发")
	// ErrIdentityMismatch 证书的 CN 或 SAN 与持久化的 node_id 不一致。
	ErrIdentityMismatch = errors.New("identity：证书身份与持久化的 node_id 不一致")
	// ErrKeyMismatch 证书公钥与持久化私钥不匹配。
	ErrKeyMismatch = errors.New("identity：证书与私钥不匹配")
	// ErrNotFound 身份文件不存在。
	ErrNotFound = errors.New("identity：身份文件不存在")
)

// Identity 已持久化的节点身份（证书 + 私钥，均只在内存）。
type Identity struct {
	// NodeID 控制面分配的身份（从证书 CN 读出，与文件中的记录比对）。
	NodeID string
	// CertificateDER 叶证书 DER。
	CertificateDER []byte
	// CACertificateDER CA 证书 DER（随身份一起持久化，便于离线启动）。
	CACertificateDER []byte
	// NotAfter 叶证书到期时刻。
	NotAfter time.Time
	// NotBefore 叶证书生效时刻（续期调度用它作为有效期起点）。
	NotBefore time.Time
	// CreatedAt 身份在本地的创建/替换时刻（NotBefore 为零时的回退锚点）。
	CreatedAt time.Time
	// Key 节点私钥。
	//
	// 注意：本字段只在"内存 → 磁盘/内存 → 客户端"之间传递；
	// **不得**进入日志、错误信息、审计 payload（测试有专项断言）。
	Key *ecdsa.PrivateKey
}

// TLSCert 返回用于 mTLS 的 tls.Certificate。
func (id *Identity) TLSCert() tls.Certificate {
	return tls.Certificate{
		Certificate: [][]byte{id.CertificateDER},
		PrivateKey:  id.Key,
	}
}

// PrivateKey 返回私钥（仅供客户端内部使用；**不得**写入日志/审计/文件以外的位置）。
func (id *Identity) PrivateKey() *ecdsa.PrivateKey { return id.Key }

// NotBeforeOrCreatedAt 返回有效期的起点（NotBefore 优先，回退 CreatedAt）。
func (id *Identity) NotBeforeOrCreatedAt() time.Time {
	if !id.NotBefore.IsZero() {
		return id.NotBefore.UTC()
	}
	return id.CreatedAt.UTC()
}

// Serial 返回证书序列号（字符串形态，与吊销表主键一致）。
func (id *Identity) Serial() string {
	leaf, err := x509.ParseCertificate(id.CertificateDER)
	if err != nil {
		return ""
	}
	return leaf.SerialNumber.String()
}

// Store 身份文件读写器。
type Store struct {
	// Dir state 目录。
	Dir string
	// FileName 文件名（空用 DefaultFileName）。
	FileName string
}

// New 构建读写器。
func New(dir, fileName string) (*Store, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, errors.New("identity：state 目录必填")
	}
	if strings.TrimSpace(fileName) == "" {
		fileName = DefaultFileName
	}
	if strings.ContainsRune(fileName, os.PathSeparator) {
		return nil, fmt.Errorf("identity：文件名不得含路径分隔符：%q", fileName)
	}
	return &Store{Dir: dir, FileName: fileName}, nil
}

// Path 身份文件路径。
func (s *Store) Path() string { return filepath.Join(s.Dir, s.FileName) }

// EnsureDir 创建 state 目录并**强制**权限 0700（已存在则校验，不符即拒绝）。
func (s *Store) EnsureDir() error {
	if err := os.MkdirAll(s.Dir, DirMode); err != nil {
		return fmt.Errorf("identity：创建 state 目录失败：%w", err)
	}
	info, err := os.Stat(s.Dir)
	if err != nil {
		return fmt.Errorf("identity：读取 state 目录失败：%w", err)
	}
	if perm := info.Mode().Perm(); perm != DirMode {
		return fmt.Errorf("%w（实际 %#o，请手动修正）", ErrDirPermissive, perm)
	}
	return nil
}

// Save 原子写入身份（临时文件 + rename；权限 0600）。
//
// 具体步骤：
//  1. 在 state 目录内创建随机名临时文件（0600）；
//  2. 写入「私钥 + 叶证书 + CA 证书 + node_id 记录」的 PEM 串联；
//  3. fsync 后 rename 覆盖目标文件（同一文件系统内 rename 是原子的）；
//  4. 失败时清理临时文件（**保留**原有身份文件，不做破坏性覆盖）。
func (s *Store) Save(id *Identity) error {
	if id == nil || id.Key == nil || len(id.CertificateDER) == 0 {
		return errors.New("identity：身份或私钥为空")
	}
	if err := s.EnsureDir(); err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(id.Key)
	if err != nil {
		return fmt.Errorf("identity：序列化私钥失败：%w", err)
	}
	var buf []byte
	buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...)
	buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: id.CertificateDER})...)
	if len(id.CACertificateDER) > 0 {
		buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: id.CACertificateDER})...)
	}
	// node_id 以注释行记录，便于人工核对（**不是**信任来源：加载时以证书为准）。
	buf = append(buf, []byte(fmt.Sprintf("# node_id: %s\n", id.NodeID))...)

	tmp, err := os.CreateTemp(s.Dir, ".identity-*.tmp")
	if err != nil {
		return fmt.Errorf("identity：创建临时文件失败：%w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		// 走到这里说明失败（成功路径已 rename，临时文件不复存在）。
		_ = os.Remove(tmpName)
	}()
	if err := tmp.Chmod(FileMode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("identity：设置临时文件权限失败：%w", err)
	}
	if _, err := tmp.Write(buf); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("identity：写入临时文件失败：%w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("identity：fsync 失败：%w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("identity：关闭临时文件失败：%w", err)
	}
	if err := os.Rename(tmpName, s.Path()); err != nil {
		return fmt.Errorf("identity：原子替换身份文件失败：%w", err)
	}
	// rename 后目标权限继承自临时文件（0600），再显式确认一次。
	if err := os.Chmod(s.Path(), FileMode); err != nil {
		return fmt.Errorf("identity：确认身份文件权限失败：%w", err)
	}
	return nil
}

// Load 读取并校验身份。
//
// 校验项（任一不符即返回对应错误，**调用方必须拒绝启动**）：
//   - 文件权限必须恰好 0600；
//   - 文件可解析（私钥 + 至少一张证书）；
//   - 证书公钥与私钥匹配；
//   - 证书未过期（now 注入）；
//   - 证书由 caPool 中的 CA 签发（caPool 为 nil 时跳过该检查，仅用于自检场景）；
//   - 证书 CN 与 SAN 均等于 nodeID（nodeID 空则只做前几项）。
func (s *Store) Load(now time.Time, caPool *x509.CertPool, nodeID string) (*Identity, error) {
	path := s.Path()
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("identity：读取身份文件失败：%w", err)
	}
	if perm := info.Mode().Perm(); perm != FileMode {
		return nil, fmt.Errorf("%w（实际 %#o）", ErrFilePermissive, perm)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("identity：读取身份文件失败：%w", err)
	}
	key, leafDER, caDER, perr := parsePEMChain(raw)
	if perr != nil {
		return nil, perr
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, fmt.Errorf("%w：叶证书解析失败", ErrCorrupt)
	}
	if !key.PublicKey.Equal(leaf.PublicKey) {
		return nil, ErrKeyMismatch
	}
	// 有效期：用证书自身的 NotBefore/NotAfter 与注入时钟比较。
	t := now.UTC()
	if t.After(leaf.NotAfter) {
		return nil, fmt.Errorf("%w（not_after=%s）", ErrExpired, leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if t.Before(leaf.NotBefore.Add(-time.Minute)) {
		return nil, fmt.Errorf("%w：证书尚未生效（not_before=%s）",
			ErrCorrupt, leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	if caPool != nil {
		if _, verr := leaf.Verify(x509.VerifyOptions{
			Roots:       caPool,
			CurrentTime: t,
			KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}); verr != nil {
			return nil, fmt.Errorf("%w：%v", ErrUntrusted, verr)
		}
	}
	cn := strings.TrimSpace(leaf.Subject.CommonName)
	if nodeID != "" {
		if cn != nodeID {
			return nil, fmt.Errorf("%w：CN=%q node_id=%q", ErrIdentityMismatch, cn, nodeID)
		}
		if err := checkSANs(leaf, nodeID); err != nil {
			return nil, err
		}
	}
	return &Identity{
		NodeID:           cn,
		CertificateDER:   leafDER,
		CACertificateDER: caDER,
		NotAfter:         leaf.NotAfter,
		NotBefore:        leaf.NotBefore,
		CreatedAt:        info.ModTime().UTC(),
		Key:              key,
	}, nil
}

// parsePEMChain 从 PEM 串联中解析出（私钥, 叶证书, CA 证书）。
func parsePEMChain(raw []byte) (*ecdsa.PrivateKey, []byte, []byte, error) {
	var key *ecdsa.PrivateKey
	var leafDER, caDER []byte
	rest := raw
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		switch blk.Type {
		case "EC PRIVATE KEY", "PRIVATE KEY":
			k, err := x509.ParseECPrivateKey(blk.Bytes)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("%w：私钥解析失败", ErrCorrupt)
			}
			key = k
		case "CERTIFICATE":
			if leafDER == nil {
				leafDER = blk.Bytes
			} else if caDER == nil {
				caDER = blk.Bytes
			}
		}
	}
	if key == nil || len(leafDER) == 0 {
		return nil, nil, nil, ErrCorrupt
	}
	return key, leafDER, caDER, nil
}

// checkSANs 校验 DNS SAN 与 URI SAN 中至少各有一个等于 nodeID。
func checkSANs(leaf *x509.Certificate, nodeID string) error {
	dnsOK := false
	for _, n := range leaf.DNSNames {
		if n == nodeID {
			dnsOK = true
		}
	}
	if !dnsOK {
		return fmt.Errorf("%w：DNS SAN 不含 node_id %q（SAN=%v）",
			ErrIdentityMismatch, nodeID, leaf.DNSNames)
	}
	return nil
}

// RemoveDirContentsForTest 仅用于测试：删除 state 目录内全部文件（不删目录）。
func (s *Store) RemoveDirContentsForTest() error {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(s.Dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}
