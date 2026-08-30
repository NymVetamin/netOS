// Package config описывает полную декларативную конфигурацию роутера.
//
// Весь документ целиком сериализуется в JSON и хранится одной строкой в
// таблице revisions. Подсистемы получают старый и новый Config, вычисляют
// разницу и приводят систему к новому состоянию.
//
// Правила для этого пакета:
//   - никаких вызовов системы, только данные и валидация;
//   - каждое поле, добавленное сюда, должно иметь разумное значение по
//     умолчанию, иначе обновление сломает существующие установки;
//   - идентификаторы (ID) стабильны на всём протяжении жизни объекта: от них
//     зависят номера routing-таблиц, fwmark и имена интерфейсов;
//   - всё, что netOS применяет к системе, обязано быть здесь видимым. Скрытых
//     правил, которые генерируются мимо конфигурации, быть не должно:
//     администратор должен видеть в панели ровно то, что окажется в ядре.
package config

// Version — версия схемы конфигурации.
const Version = 2

// Собственный протокол маршрутов netOS.
//
// Им помечаются маршруты, поставленные роутером: в выводе ip route сразу
// видно, кто их добавил, а подсистемы не удаляют работу друг друга.
// В командах используется число, а не имя: имя становится известно системе
// только после записи файла протоколов, а маршруты назначаются раньше.
const (
	RouteProto     = 201
	RouteProtoName = "netos"
)

// maxInterfaceName — предел ядра на имя сетевого интерфейса (IFNAMSIZ - 1).
// Имена, которые netOS строит сам (ppp-<id> и подобные), обязаны в него
// помещаться, иначе правила файрволла сошлются на несуществующий интерфейс.
const maxInterfaceName = 15

// Config — корень дерева конфигурации.
type Config struct {
	Version    int         `json:"version"`
	System     System      `json:"system"`
	IPv6       IPv6Policy  `json:"ipv6"`
	Components []Component `json:"components"`
	Interfaces []Interface `json:"interfaces"`
	Networks   []Network   `json:"networks"`
	WANs       []WAN       `json:"wans"`
	MultiWAN   MultiWAN    `json:"multiwan"`
	Routing    Routing     `json:"routing"`
	Firewall   Firewall    `json:"firewall"`
	DHCP       DHCP        `json:"dhcp"`
	DNS        DNS         `json:"dns"`
	Clients    []Client    `json:"clients"`
	Channels   []Channel   `json:"channels"`
	Policies   []Policy    `json:"policies"`
	VPNServers []VPNServer `json:"vpn_servers"`
	WiFi       []WiFiRadio `json:"wifi"`
}

// ---------------------------------------------------------------------------
// Система
// ---------------------------------------------------------------------------

type System struct {
	Hostname string `json:"hostname"`
	Timezone string `json:"timezone"`
	NTP      NTP    `json:"ntp"`
	Panel    Panel  `json:"panel"`
	// NetworkBackend — чем настраивать интерфейсы:
	//   netos    — netOS управляет напрямую через iproute2 (по умолчанию);
	//   ifupdown — генерировать /etc/network/interfaces для службы networking;
	//   networkd — генерировать файлы для systemd-networkd.
	// Выбор за администратором: на машине может быть принятый в организации
	// способ настройки сети, и навязывать свой netOS не должен.
	NetworkBackend string `json:"network_backend"`
}

type NTP struct {
	Enabled bool     `json:"enabled"`
	Servers []string `json:"servers"`
}

// Panel — параметры самой веб-панели.
type Panel struct {
	Port int `json:"port"`
	// CommitTimeout — сколько секунд ждать подтверждения от админа, прежде чем
	// автоматически откатить применённую конфигурацию.
	CommitTimeout int `json:"commit_timeout"`
	TLS           TLS `json:"tls"`
}

type TLS struct {
	Mode     string `json:"mode"` // selfsigned | custom | acme
	CertFile string `json:"cert_file,omitempty"`
	KeyFile  string `json:"key_file,omitempty"`
	Domain   string `json:"domain,omitempty"`
}

// IPv6Policy управляет подавлением IPv6.
type IPv6Policy struct {
	Mode       string `json:"mode"` // off | passthrough
	FilterAAAA bool   `json:"filter_aaaa"`
}

// ---------------------------------------------------------------------------
// Компоненты
// ---------------------------------------------------------------------------

// Component — устанавливаемая часть роутера.
//
// Базовая установка netOS не тянет ничего лишнего: только панель и доступ по
// SSH. DHCP-сервер, резолверы, VPN и точка доступа ставятся отдельно, когда
// администратор действительно решит их использовать. Так роутер не обрастает
// службами, которые никто не просил, и поверхность атаки остаётся минимальной.
type Component struct {
	// ID из каталога компонентов: dnsmasq, unbound, wireguard, xray и так далее.
	ID string `json:"id"`
	// Installed — желаемое состояние. Подсистема components доводит систему до
	// него: ставит недостающее, убирает лишнее.
	Installed bool `json:"installed"`
}

// ---------------------------------------------------------------------------
// Канальный уровень
// ---------------------------------------------------------------------------

// Interface — L2-сущность: физический порт, bridge, VLAN или bond.
type Interface struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"` // physical | bridge | vlan | bond
	// Members — идентификаторы портов, включённых в мост или агрегацию.
	// Именно идентификаторы, а не имена: имя администратор меняет в панели, и
	// ссылка по имени пережила бы переименование только на бумаге.
	Members []string `json:"members,omitempty"`
	// Parent — идентификатор интерфейса, поверх которого поднят VLAN.
	Parent string `json:"parent,omitempty"`
	VLANID  int      `json:"vlan_id,omitempty"`
	MTU     int      `json:"mtu,omitempty"`
	MAC     string   `json:"mac,omitempty"`
	Enabled bool     `json:"enabled"`
}

// Network — L3-сегмент: подсеть и адрес роутера в ней.
type Network struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Interface — ID интерфейса, на котором живёт сегмент.
	Interface string `json:"interface"`
	// RouterAddress — адрес самого роутера в этом сегменте вместе с маской.
	// Он же становится шлюзом по умолчанию для клиентов сегмента.
	RouterAddress string `json:"router_address"`
	Enabled       bool   `json:"enabled"`
	// Zone — зона файрволла, к которой относится сегмент.
	Zone string `json:"zone"`
	// Isolated запрещает трафик между этим сегментом и другими сегментами.
	Isolated bool `json:"isolated"`
	// DefaultChannel — канал выхода для клиентов сегмента.
	DefaultChannel string   `json:"default_channel,omitempty"`
	DHCPPool       DHCPPool `json:"dhcp_pool"`
}

// ---------------------------------------------------------------------------
// WAN
// ---------------------------------------------------------------------------

type WAN struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Interface string `json:"interface"`
	Enabled   bool   `json:"enabled"`
	// Proto: dhcp | static | pppoe | l2tp
	Proto string `json:"proto"`
	// Для static.
	Address string   `json:"address,omitempty"`
	Gateway string   `json:"gateway,omitempty"`
	DNS     []string `json:"dns,omitempty"`
	// Для pppoe и l2tp.
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	// Server — адрес концентратора L2TP.
	Server string `json:"server,omitempty"`
	// Underlay — как получает адрес интерфейс, по которому идёт туннель L2TP.
	//
	// Провайдер сначала выдаёт адрес в своей локальной сети, и только поверх
	// него поднимается туннель до концентратора. Обычно адрес приходит по
	// DHCP — это и есть значение по умолчанию; при static берутся Address
	// и Gateway.
	Underlay string `json:"underlay,omitempty"` // dhcp | static
	// Service и AC — необязательные параметры PPPoE.
	Service string `json:"service,omitempty"`
	AC      string `json:"ac,omitempty"`
	// Metric задаёт приоритет аплинка: меньше — предпочтительнее.
	Metric int   `json:"metric"`
	Weight int   `json:"weight"`
	MTU    int   `json:"mtu,omitempty"`
	Probe  Probe `json:"probe"`
}

// Probe — проверка живости канала или аплинка.
type Probe struct {
	Enabled       bool     `json:"enabled"`
	Type          string   `json:"type"` // icmp | tcp | http
	Targets       []string `json:"targets"`
	Interval      int      `json:"interval"`
	Timeout       int      `json:"timeout"`
	FailThreshold int      `json:"fail_threshold"`
	RiseThreshold int      `json:"rise_threshold"`
}

type MultiWAN struct {
	Enabled           bool   `json:"enabled"`
	Mode              string `json:"mode"` // failover | balance
	StickyConnections bool   `json:"sticky_connections"`
}

// ---------------------------------------------------------------------------
// Маршрутизация
// ---------------------------------------------------------------------------

// Routing — всё, что относится к выбору пути пакета: статические маршруты,
// дополнительные таблицы и правила выбора таблиц.
//
// Это тот же механизм, на котором позже будет построен выбор VPN-канала для
// каждого клиента: канал получает свою таблицу, а правило направляет в неё
// помеченный трафик.
type Routing struct {
	Static []StaticRoute `json:"static"`
	Tables []RouteTable  `json:"tables"`
	Rules  []RouteRule   `json:"rules"`
}

// StaticRoute — маршрут, добавляемый вручную.
type StaticRoute struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	// Destination — подсеть назначения либо default.
	Destination string `json:"destination"`
	Gateway     string `json:"gateway,omitempty"`
	// Interface — имя интерфейса для маршрутов без шлюза.
	Interface string `json:"interface,omitempty"`
	Metric    int    `json:"metric"`
	// Table — в какую таблицу добавить. Пусто — основная.
	Table string `json:"table,omitempty"`
	// Type: unicast | blackhole | unreachable | prohibit.
	Type    string `json:"type,omitempty"`
	Comment string `json:"comment,omitempty"`
}

// RouteTable — дополнительная таблица маршрутизации.
type RouteTable struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Number — номер таблицы в ядре.
	Number int `json:"number"`
	// System помечает таблицы, созданные netOS под каналы: их номера завязаны
	// на индексы каналов, менять их вручную нельзя.
	System  bool   `json:"system"`
	Comment string `json:"comment,omitempty"`
}

// RouteRule — правило выбора таблицы (ip rule).
type RouteRule struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	// Priority — чем меньше, тем раньше правило проверяется.
	Priority int `json:"priority"`
	// Селекторы: пустое поле означает «любой».
	From      string `json:"from,omitempty"`
	To        string `json:"to,omitempty"`
	FwMark    string `json:"fwmark,omitempty"`
	Interface string `json:"interface,omitempty"`
	// Table — куда направить совпавший трафик.
	Table   string `json:"table"`
	System  bool   `json:"system"`
	Comment string `json:"comment,omitempty"`
}

// ---------------------------------------------------------------------------
// Файрволл
// ---------------------------------------------------------------------------

// Firewall построен на трёх цепочках по зонам: lan, wan, vpn. Пакет попадает
// в цепочку по интерфейсу, с которого пришёл, и дальше обрабатывается списком
// правил сверху вниз. Правил ровно столько, сколько видно в панели: netOS не
// добавляет ничего от себя незаметно.
//
// Системные правила (аварийный доступ, ответы на установленные соединения и
// подобные) присутствуют в этом же списке с признаком System. Их можно
// выключить, но нельзя удалить — чтобы администратор понимал, что именно
// защищает его доступ к роутеру, и мог это осознанно снять.
type Firewall struct {
	Enabled bool `json:"enabled"`
	// Zones задают политику по умолчанию для трафика, не совпавшего ни с одним
	// правилом зоны. Политика зоны действует на вход и на форвард.
	Zones []Zone `json:"zones"`
	// OutputPolicy — что делать с трафиком самого роутера, не совпавшим ни с
	// одним правилом. Вынесено отдельно от зон намеренно: запретить роутеру
	// исходящие — решение куда более серьёзное, чем закрыть вход, и прятать
	// его в общую политику зоны нельзя.
	OutputPolicy string `json:"output_policy"`
	// Rules — единый упорядоченный список правил.
	Rules []FirewallRule `json:"rules"`
	// NAT — трансляция адресов: и подмена источника на выходе, и проброс
	// портов внутрь. Это две стороны одного механизма, и держать их в разных
	// разделах панели было ошибкой.
	NAT []NATRule `json:"nat"`
}

// Zone — группа интерфейсов с общей политикой.
type Zone struct {
	Name        string `json:"name"` // lan | wan | vpn
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	// Policy — что делать с пакетом, не совпавшим ни с одним правилом зоны.
	Policy string `json:"policy"` // accept | drop | reject
	// MSSClamp чинит проблемы с MTU на PPPoE и туннелях.
	MSSClamp bool `json:"mss_clamp"`
}

// FirewallRule — одно правило. Порядок в списке = порядок в цепочке.
type FirewallRule struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	// System — правило создано netOS. Удалению не подлежит, выключению — да.
	System bool `json:"system"`
	// Zone — цепочка, в которую попадает правило: определяется зоной входящего
	// интерфейса.
	Zone string `json:"zone"`
	// Flow — направление трафика, теми же словами, что и цепочки ядра:
	//   in      — вход: пакет адресован самому роутеру (INPUT);
	//   out     — выход: пакет отправлен самим роутером (OUTPUT);
	//   forward — форвард: пакет идёт сквозь роутер (FORWARD).
	//
	// Направления «во все сразу» намеренно нет: одно правило — одна цепочка.
	// Иначе правило расползается по цепочкам, где оно не нужно, и заметить это
	// можно только вычитывая вывод iptables-save.
	//
	// Zone означает зону того интерфейса, который у направления единственный:
	// входящего для in и forward, исходящего для out.
	Flow string `json:"flow"`
	// DstZone задаёт зону выходного интерфейса и осмысленна только для
	// форварда: у входа и выхода второй зоны просто нет.
	DstZone string `json:"dst_zone,omitempty"`
	Action  string `json:"action"` // accept | drop | reject | continue
	// Селекторы. Пустое поле означает «любой».
	Interface string    `json:"interface,omitempty"`
	Protocol  string    `json:"protocol,omitempty"`
	SrcIP     string    `json:"src_ip,omitempty"`
	DstIP     string    `json:"dst_ip,omitempty"`
	SrcMAC    string    `json:"src_mac,omitempty"`
	SrcPort   string    `json:"src_port,omitempty"`
	DstPort   string    `json:"dst_port,omitempty"`
	ConnState string    `json:"conn_state,omitempty"` // new,established,related,invalid
	Schedule  *Schedule `json:"schedule,omitempty"`
	Log       bool      `json:"log"`
	Comment   string    `json:"comment,omitempty"`
}

type Schedule struct {
	Days      []string `json:"days"`
	TimeStart string   `json:"time_start"`
	TimeStop  string   `json:"time_stop"`
}

// NATRule — правило трансляции адресов.
//
// Направление source подменяет адрес отправителя на выходе из роутера: это
// то, благодаря чему клиенты локальной сети видны в интернете как сам роутер.
// Направление destination подменяет адрес получателя на входе: обращение
// снаружи на порт роутера уезжает на устройство внутри сети.
type NATRule struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	System  bool   `json:"system"`
	// Direction: source (подмена отправителя) | destination (проброс внутрь).
	Direction string `json:"direction"`

	// --- подмена отправителя ---
	//
	// Interface — через какой интерфейс уходит трафик. Задаётся именно
	// интерфейс, а не зона: в ядре правило всё равно привязано к интерфейсу,
	// и лишний слой абстракции только мешает понять, что произойдёт.
	Interface string `json:"interface,omitempty"`
	// Source ограничивает правило отправителями из этой подсети.
	Source string `json:"source,omitempty"`
	// ToSource — адрес, на который подменять. Пусто означает маскарад:
	// подставится текущий адрес интерфейса, что и нужно на динамическом
	// подключении, где адрес меняется.
	ToSource string `json:"to_source,omitempty"`

	// --- проброс внутрь ---
	Protocol string `json:"protocol,omitempty"`
	// ExtPort — порт, на который обращаются снаружи.
	ExtPort string `json:"ext_port,omitempty"`
	// DestIP и DestPort — куда перенаправить.
	DestIP   string `json:"dest_ip,omitempty"`
	DestPort string `json:"dest_port,omitempty"`
	// AllowFrom ограничивает, с каких адресов принимать обращения.
	AllowFrom string `json:"allow_from,omitempty"`

	Comment string `json:"comment,omitempty"`
}

// ---------------------------------------------------------------------------
// DHCP
// ---------------------------------------------------------------------------

type DHCP struct {
	// Provider выбирается в разделе компонентов: здесь только то, что
	// относится к самой выдаче адресов.
	Provider        string        `json:"provider"`
	Enabled         bool          `json:"enabled"`
	Reservations    []Reservation `json:"reservations"`
	AdvancedOptions string        `json:"advanced_options,omitempty"`
}

type DHCPPool struct {
	Enabled    bool              `json:"enabled"`
	Start      string            `json:"start"`
	End        string            `json:"end"`
	LeaseTime  int               `json:"lease_time"`
	DNSServers []string          `json:"dns_servers,omitempty"`
	Gateway    string            `json:"gateway,omitempty"`
	Domain     string            `json:"domain,omitempty"`
	Options    map[string]string `json:"options,omitempty"`
}

type Reservation struct {
	ID       string `json:"id"`
	Enabled  bool   `json:"enabled"`
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`
	Network  string `json:"network"`
	Comment  string `json:"comment,omitempty"`
}

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------

type DNS struct {
	Provider         string         `json:"provider"`
	Enabled          bool           `json:"enabled"`
	Port             int            `json:"port"`
	Upstreams        []Upstream     `json:"upstreams"`
	Bootstrap        []string       `json:"bootstrap"`
	CacheSize        int            `json:"cache_size"`
	DNSSEC           bool           `json:"dnssec"`
	LocalDomain      string         `json:"local_domain"`
	StaticRecords    []DNSRecord    `json:"static_records"`
	SplitRules       []DNSSplitRule `json:"split_rules"`
	Blocklists       []Blocklist    `json:"blocklists"`
	RebindProtection bool           `json:"rebind_protection"`
	ForceLocal       bool           `json:"force_local"`
	QueryLog         bool           `json:"query_log"`
	AdvancedOptions  string         `json:"advanced_options,omitempty"`
}

type Upstream struct {
	ID      string `json:"id"`
	Type    string `json:"type"` // plain | dot | doh | doq
	Address string `json:"address"`
	Channel string `json:"channel,omitempty"`
	Enabled bool   `json:"enabled"`
	Comment string `json:"comment,omitempty"`
}

type DNSRecord struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

type DNSSplitRule struct {
	ID       string   `json:"id"`
	Domains  []string `json:"domains"`
	Upstream string   `json:"upstream,omitempty"`
	Channel  string   `json:"channel,omitempty"`
	Enabled  bool     `json:"enabled"`
}

type Blocklist struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
}

// ---------------------------------------------------------------------------
// Клиенты
// ---------------------------------------------------------------------------

type Client struct {
	ID       string `json:"id"`
	MAC      string `json:"mac"`
	Name     string `json:"name"`
	Network  string `json:"network,omitempty"`
	Channel  string `json:"channel,omitempty"`
	Blocked  bool   `json:"blocked"`
	DownKbit int    `json:"down_kbit"`
	UpKbit   int    `json:"up_kbit"`
	Comment  string `json:"comment,omitempty"`
}

// ---------------------------------------------------------------------------
// Каналы и политики
// ---------------------------------------------------------------------------

type Channel struct {
	ID       string         `json:"id"`
	Index    int            `json:"index"`
	Name     string         `json:"name"`
	Enabled  bool           `json:"enabled"`
	Type     string         `json:"type"` // direct | wireguard | xray | openconnect | l2tp | ikev2
	Mode     string         `json:"mode"` // tun | tproxy | socks
	FailMode string         `json:"fail_mode"`
	Fallback string         `json:"fallback,omitempty"`
	Probe    Probe          `json:"probe"`
	Config   map[string]any `json:"config,omitempty"`
}

type Policy struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Enabled   bool      `json:"enabled"`
	Priority  int       `json:"priority"`
	Channel   string    `json:"channel"`
	SrcIP     string    `json:"src_ip,omitempty"`
	SrcMAC    string    `json:"src_mac,omitempty"`
	Network   string    `json:"network,omitempty"`
	VPNServer string    `json:"vpn_server,omitempty"`
	VPNPeer   string    `json:"vpn_peer,omitempty"`
	Protocol  string    `json:"protocol,omitempty"`
	DstPort   string    `json:"dst_port,omitempty"`
	DstIP     string    `json:"dst_ip,omitempty"`
	Domains   []string  `json:"domains,omitempty"`
	Schedule  *Schedule `json:"schedule,omitempty"`
	Comment   string    `json:"comment,omitempty"`
}

type VPNServer struct {
	ID             string         `json:"id"`
	Index          int            `json:"index"`
	Name           string         `json:"name"`
	Enabled        bool           `json:"enabled"`
	Type           string         `json:"type"`
	Subnet         string         `json:"subnet"`
	Port           int            `json:"port"`
	DefaultChannel string         `json:"default_channel,omitempty"`
	Peers          []VPNPeer      `json:"peers"`
	Config         map[string]any `json:"config,omitempty"`
}

type VPNPeer struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Enabled     bool              `json:"enabled"`
	Address     string            `json:"address"`
	Channel     string            `json:"channel,omitempty"`
	Credentials map[string]string `json:"credentials,omitempty"`
	Comment     string            `json:"comment,omitempty"`
}

// ---------------------------------------------------------------------------
// Wi-Fi
// ---------------------------------------------------------------------------

type WiFiRadio struct {
	ID      string     `json:"id"`
	Device  string     `json:"device"`
	Enabled bool       `json:"enabled"`
	Band    string     `json:"band"`
	Channel int        `json:"channel"`
	Width   int        `json:"width"`
	Country string     `json:"country"`
	TxPower int        `json:"tx_power,omitempty"`
	SSIDs   []WiFiSSID `json:"ssids"`
}

type WiFiSSID struct {
	ID       string `json:"id"`
	SSID     string `json:"ssid"`
	Enabled  bool   `json:"enabled"`
	Security string `json:"security"`
	Password string `json:"password,omitempty"`
	Network  string `json:"network"`
	Hidden   bool   `json:"hidden"`
	Isolate  bool   `json:"isolate"`
}
