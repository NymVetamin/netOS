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
//   - метаданные plan/sensitivity описывают поле в плане изменений; новое
//     сериализуемое поле должно иметь название и явную классификацию значения.
//     format/reference задают только отображение, не меняя единицы хранения.
package config

// Version — версия схемы конфигурации.
const Version = 3

// Собственный протокол маршрутов аплинков netOS. Пользовательская статика
// использует proto static; 202 оставлен только для очистки маршрутов старых версий.
// В командах используется число: имя становится известно после записи файла.
const (
	RouteProto       = 201
	RouteProtoName   = "netos"
	StaticRouteProto = 202
)

// maxInterfaceName — предел ядра на имя сетевого интерфейса (IFNAMSIZ - 1).
// Имена, которые netOS строит сам (ppp-<id> и подобные), обязаны в него
// помещаться, иначе правила файрволла сошлются на несуществующий интерфейс.
const maxInterfaceName = 15

// Config — корень дерева конфигурации.
type Config struct {
	IPTV           IPTV           `json:"iptv" plan:"IPTV" sensitivity:"public"`
	TrafficMonitor TrafficMonitor `json:"traffic_monitor" plan:"Учёт трафика клиентов" sensitivity:"public"`
	Socks          Socks          `json:"socks" plan:"Прокси SOCKS" sensitivity:"public"`
	Version        int            `json:"version" plan:"Версия схемы" sensitivity:"public"`
	System         System         `json:"system" plan:"Система" sensitivity:"public"`
	IPv6           IPv6Policy     `json:"ipv6" plan:"IPv6" sensitivity:"public"`
	Components     []Component    `json:"components" plan:"Компоненты" sensitivity:"public"`
	Interfaces     []Interface    `json:"interfaces" plan:"Интерфейсы" sensitivity:"public"`
	Networks       []Network      `json:"networks" plan:"Локальные сети" sensitivity:"public"`
	WANs           []WAN          `json:"wans" plan:"Аплинки" sensitivity:"public"`
	MultiWAN       MultiWAN       `json:"multiwan" plan:"Несколько аплинков" sensitivity:"public"`
	Routing        Routing        `json:"routing" plan:"Маршрутизация" sensitivity:"public"`
	Firewall       Firewall       `json:"firewall" plan:"Файрвол" sensitivity:"public"`
	DHCP           DHCP           `json:"dhcp" plan:"DHCP" sensitivity:"public"`
	DNS            DNS            `json:"dns" plan:"DNS" sensitivity:"public"`
	Clients        []Client       `json:"clients" plan:"Клиенты" sensitivity:"public"`
	Channels       []Channel      `json:"channels" plan:"Интернет-каналы" sensitivity:"public"`
	Policies       []Policy       `json:"policies" plan:"Политики" sensitivity:"public"`
	VPNServers     []VPNServer    `json:"vpn_servers" plan:"VPN-серверы" sensitivity:"public"`
	WiFi           []WiFiRadio    `json:"wifi" plan:"Wi-Fi" sensitivity:"public"`
	QoS            QoS            `json:"qos" plan:"Управление скоростью" sensitivity:"public"`
	DDNS           DDNS           `json:"ddns" plan:"Динамический DNS" sensitivity:"public"`
	Samba          Samba          `json:"samba" plan:"Общий доступ к файлам" sensitivity:"public"`
}

// TrafficMonitor is opt-in; disabling stops collection without erasing history.
type TrafficMonitor struct {
	Enabled bool `json:"enabled" plan:"Состояние" sensitivity:"public" format:"switch"`
}

// ---------------------------------------------------------------------------
// Система
// ---------------------------------------------------------------------------

type System struct {
	Hostname string `json:"hostname" plan:"Имя устройства" sensitivity:"public"`
	Timezone string `json:"timezone" plan:"Часовой пояс" sensitivity:"public"`
	NTP      NTP    `json:"ntp" plan:"Синхронизация времени" sensitivity:"public"`
	Panel    Panel  `json:"panel" plan:"Веб-панель" sensitivity:"public"`
	// NetworkBackend — чем настраивать интерфейсы:
	//   netos    — netOS управляет напрямую через iproute2 (по умолчанию);
	//   ifupdown — генерировать /etc/network/interfaces для службы networking;
	//   networkd — генерировать файлы для systemd-networkd.
	// Выбор за администратором: на машине может быть принятый в организации
	// способ настройки сети, и навязывать свой netOS не должен.
	NetworkBackend string `json:"network_backend" plan:"Управление интерфейсами" sensitivity:"public"`
}

type NTP struct {
	Enabled bool     `json:"enabled" plan:"Состояние" sensitivity:"public" format:"switch"`
	Servers []string `json:"servers" plan:"Серверы" sensitivity:"public"`
}

// Panel — параметры самой веб-панели.
type Panel struct {
	Port int `json:"port" plan:"Порт" sensitivity:"public"`
	// CommitTimeout — сколько секунд ждать подтверждения от админа, прежде чем
	// автоматически откатить применённую конфигурацию.
	CommitTimeout int `json:"commit_timeout" plan:"Ожидание подтверждения, с" sensitivity:"public"`
	TLS           TLS `json:"tls" plan:"TLS" sensitivity:"public"`
}

type TLS struct {
	Mode      string `json:"mode" plan:"Режим" sensitivity:"public"` // selfsigned | custom | acme
	CertFile  string `json:"cert_file,omitempty" plan:"Файл сертификата" sensitivity:"public"`
	KeyFile   string `json:"key_file,omitempty" plan:"Файл ключа" sensitivity:"public"`
	Domain    string `json:"domain,omitempty" plan:"Домен" sensitivity:"public"`
	Email     string `json:"email,omitempty" plan:"Электронная почта" sensitivity:"public"`
	AcceptTOS bool   `json:"accept_tos,omitempty" plan:"Согласие с условиями ACME" sensitivity:"public"`
}

// IPv6Policy управляет подавлением IPv6.
type IPv6Policy struct {
	Mode       string `json:"mode" plan:"Режим" sensitivity:"public"` // off | passthrough
	FilterAAAA bool   `json:"filter_aaaa" plan:"Фильтрация AAAA" sensitivity:"public"`
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
	ID string `json:"id" plan:"Идентификатор" sensitivity:"public" identity:"true"`
	// Installed — желаемое состояние. Подсистема components доводит систему до
	// него: ставит недостающее, убирает лишнее.
	Installed bool `json:"installed" plan:"Установка компонента" sensitivity:"public"`
}

// ---------------------------------------------------------------------------
// Канальный уровень
// ---------------------------------------------------------------------------

// Interface — L2-сущность: физический порт, bridge, VLAN или bond.
type Interface struct {
	Label    string `json:"label,omitempty" plan:"Подпись" sensitivity:"public"`
	LinkMode string `json:"link_mode,omitempty" plan:"Режим соединения" sensitivity:"public"`
	ID       string `json:"id" plan:"Идентификатор" sensitivity:"public" identity:"true"`
	Name     string `json:"name" plan:"Название" sensitivity:"public"`
	Type     string `json:"type" plan:"Тип" sensitivity:"public"` // physical | bridge | vlan | bond
	// Members — идентификаторы портов, включённых в мост или агрегацию.
	// Именно идентификаторы, а не имена: имя администратор меняет в панели, и
	// ссылка по имени пережила бы переименование только на бумаге.
	Members []string `json:"members,omitempty" plan:"Участники" sensitivity:"public"`
	// Parent — идентификатор интерфейса, поверх которого поднят VLAN.
	Parent  string `json:"parent,omitempty" plan:"Родительский интерфейс" sensitivity:"public"`
	VLANID  int    `json:"vlan_id,omitempty" plan:"Номер VLAN" sensitivity:"public"`
	MTU     int    `json:"mtu,omitempty" plan:"MTU" sensitivity:"public"`
	MAC     string `json:"mac,omitempty" plan:"MAC-адрес" sensitivity:"public"`
	Enabled bool   `json:"enabled" plan:"Состояние" sensitivity:"public" format:"switch"`
}

// Network — L3-сегмент: подсеть и адрес роутера в ней.
type Network struct {
	ID   string `json:"id" plan:"Идентификатор" sensitivity:"public" identity:"true"`
	Name string `json:"name" plan:"Название" sensitivity:"public"`
	// Interface — ID интерфейса, на котором живёт сегмент.
	Interface string `json:"interface" plan:"Интерфейс" sensitivity:"public"`
	// RouterAddress — адрес самого роутера в этом сегменте вместе с маской.
	// Он же становится шлюзом по умолчанию для клиентов сегмента.
	RouterAddress string `json:"router_address" plan:"Адрес роутера" sensitivity:"public"`
	Enabled       bool   `json:"enabled" plan:"Состояние" sensitivity:"public" format:"switch"`
	// Zone — зона файрволла, к которой относится сегмент.
	Zone string `json:"zone" plan:"Зона" sensitivity:"public"`
	// Isolated запрещает трафик между этим сегментом и другими сегментами.
	Isolated bool `json:"isolated" plan:"Изоляция" sensitivity:"public"`
	// DefaultChannel — канал выхода для клиентов сегмента.
	DefaultChannel string   `json:"default_channel,omitempty" plan:"Канал выхода по умолчанию" sensitivity:"public" reference:"channel"`
	DHCPPool       DHCPPool `json:"dhcp_pool" plan:"Пул DHCP" sensitivity:"public"`
}

// ---------------------------------------------------------------------------
// WAN
// ---------------------------------------------------------------------------

type WAN struct {
	SecretsSet map[string]bool `json:"secrets_set,omitempty" plan:"-" sensitivity:"secret"` // Read response metadata, stripped before saving.

	ID        string `json:"id" plan:"Идентификатор" sensitivity:"public" identity:"true"`
	Index     int    `json:"index" plan:"Номер" sensitivity:"public"`
	Name      string `json:"name" plan:"Название" sensitivity:"public"`
	Interface string `json:"interface" plan:"Интерфейс" sensitivity:"public"`
	Enabled   bool   `json:"enabled" plan:"Состояние" sensitivity:"public" format:"switch"`
	// Proto: dhcp | static | pppoe | l2tp
	Proto string `json:"proto" plan:"Протокол" sensitivity:"public"`
	// Для static.
	Address string `json:"address,omitempty" plan:"Адрес" sensitivity:"public"`
	Gateway string `json:"gateway,omitempty" plan:"Шлюз" sensitivity:"public"`
	// Для pppoe и l2tp.
	Username string `json:"username,omitempty" plan:"Логин" sensitivity:"public"`
	Password string `json:"password,omitempty" plan:"Пароль" sensitivity:"secret"`
	// Server — адрес концентратора L2TP.
	Server string `json:"server,omitempty" plan:"Сервер" sensitivity:"public"`
	// Underlay — как получает адрес интерфейс, по которому идёт туннель L2TP.
	//
	// Провайдер сначала выдаёт адрес в своей локальной сети, и только поверх
	// него поднимается туннель до концентратора. Обычно адрес приходит по
	// DHCP — это и есть значение по умолчанию; при static берутся Address
	// и Gateway.
	Underlay string `json:"underlay,omitempty" plan:"Транспортный канал" sensitivity:"public" reference:"channel"` // dhcp | static
	// Service и AC — необязательные параметры PPPoE.
	Service string `json:"service,omitempty" plan:"Служба" sensitivity:"public"`
	AC      string `json:"ac,omitempty" plan:"Концентратор PPPoE" sensitivity:"public"`
	// Metric задаёт приоритет аплинка: меньше — предпочтительнее.
	Metric int   `json:"metric" plan:"Метрика" sensitivity:"public"`
	Weight int   `json:"weight" plan:"Вес" sensitivity:"public"`
	MTU    int   `json:"mtu,omitempty" plan:"MTU" sensitivity:"public"`
	Probe  Probe `json:"probe" plan:"Проверка канала" sensitivity:"public"`
}

// Probe — проверка живости канала или аплинка.
type Probe struct {
	Enabled       bool     `json:"enabled" plan:"Состояние" sensitivity:"public" format:"switch"`
	Type          string   `json:"type" plan:"Тип" sensitivity:"public"` // icmp | tcp | http
	Targets       []string `json:"targets" plan:"Цели проверки" sensitivity:"public"`
	TCPRequest    string   `json:"tcp_request,omitempty" plan:"Запрос проверки TCP" sensitivity:"secret"`
	TCPResponse   string   `json:"tcp_response,omitempty" plan:"Ожидаемый ответ TCP" sensitivity:"secret"` // Required response prefix for an application-level TCP probe.
	Interval      int      `json:"interval" plan:"Интервал, с" sensitivity:"public"`
	Timeout       int      `json:"timeout" plan:"Таймаут, с" sensitivity:"public"`
	FailThreshold int      `json:"fail_threshold" plan:"Ошибок до отказа" sensitivity:"public"`
	RiseThreshold int      `json:"rise_threshold" plan:"Успехов до возврата" sensitivity:"public"`
}

type MultiWAN struct {
	Enabled           bool   `json:"enabled" plan:"Состояние" sensitivity:"public" format:"switch"`
	Mode              string `json:"mode" plan:"Режим" sensitivity:"public"` // failover | balance
	StickyConnections bool   `json:"sticky_connections" plan:"Закрепление соединений" sensitivity:"public"`
}

// QoS управляет очередями на интернет-каналах. Скорости задаются немного ниже
// тарифа провайдера, чтобы очередь находилась на роутере, а не у провайдера.
type QoS struct {
	Enabled bool     `json:"enabled" plan:"Состояние" sensitivity:"public" format:"switch"`
	WANs    []QoSWAN `json:"wans" plan:"Аплинки" sensitivity:"public"`
}

type QoSWAN struct {
	WAN          string `json:"wan" plan:"Аплинк" sensitivity:"public"`
	UploadKbit   int    `json:"upload_kbit" plan:"Отдача, Мбит/с" sensitivity:"public" format:"mbit"`
	DownloadKbit int    `json:"download_kbit" plan:"Загрузка, Мбит/с" sensitivity:"public" format:"mbit"`
	Diffserv     string `json:"diffserv" plan:"Приоритизация трафика" sensitivity:"public"` // besteffort | diffserv3 | diffserv4 | diffserv8
}

// DDNS keeps one public DNS A record in sync with the router address.
type DDNS struct {
	SecretsSet map[string]bool `json:"secrets_set,omitempty" plan:"-" sensitivity:"secret"` // Read response metadata, stripped before saving.

	Enabled       bool   `json:"enabled" plan:"Состояние" sensitivity:"public" format:"switch"`
	Provider      string `json:"provider" plan:"Служба" sensitivity:"public"` // duckdns | cloudflare | noip
	Hostname      string `json:"hostname" plan:"Имя устройства" sensitivity:"public"`
	WAN           string `json:"wan,omitempty" plan:"Аплинк" sensitivity:"public"`
	AddressSource string `json:"address_source" plan:"Источник адреса" sensitivity:"public"` // interface | web
	Interval      int    `json:"interval" plan:"Интервал, с" sensitivity:"public"`           // seconds
	Token         string `json:"token,omitempty" plan:"Токен" sensitivity:"secret"`
	Username      string `json:"username,omitempty" plan:"Логин" sensitivity:"public"`
	Password      string `json:"password,omitempty" plan:"Пароль" sensitivity:"secret"`
	ZoneID        string `json:"zone_id,omitempty" plan:"Идентификатор зоны" sensitivity:"public"`
	RecordID      string `json:"record_id,omitempty" plan:"Идентификатор записи" sensitivity:"public"`
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
	Static []StaticRoute `json:"static" plan:"Статические маршруты" sensitivity:"public"`
	Tables []RouteTable  `json:"tables" plan:"Таблицы" sensitivity:"public"`
	Rules  []RouteRule   `json:"rules" plan:"Правила" sensitivity:"public"`
}

// StaticRoute — маршрут, добавляемый вручную.
type StaticRoute struct {
	ID      string `json:"id" plan:"Идентификатор" sensitivity:"public" identity:"true"`
	Name    string `json:"name" plan:"Название" sensitivity:"public"`
	Enabled bool   `json:"enabled" plan:"Состояние" sensitivity:"public" format:"switch"`
	// Destination — подсеть назначения либо default.
	Destination string `json:"destination" plan:"Назначение" sensitivity:"public"`
	Gateway     string `json:"gateway,omitempty" plan:"Шлюз" sensitivity:"public"`
	// Interface — имя интерфейса для маршрутов без шлюза.
	Interface string `json:"interface,omitempty" plan:"Интерфейс" sensitivity:"public"`
	Metric    int    `json:"metric" plan:"Метрика" sensitivity:"public"`
	// Table — в какую таблицу добавить. Пусто — основная.
	Table string `json:"table,omitempty" plan:"Таблица" sensitivity:"public"`
	// Type: unicast | blackhole | unreachable | prohibit.
	Type    string `json:"type,omitempty" plan:"Тип" sensitivity:"public"`
	Comment string `json:"comment,omitempty" plan:"Комментарий" sensitivity:"public"`
}

// RouteTable — дополнительная таблица маршрутизации.
type RouteTable struct {
	ID   string `json:"id" plan:"Идентификатор" sensitivity:"public" identity:"true"`
	Name string `json:"name" plan:"Название" sensitivity:"public"`
	// Number — номер таблицы в ядре.
	Number int `json:"number" plan:"Номер таблицы" sensitivity:"public"`
	// System помечает таблицы, созданные netOS под каналы: их номера завязаны
	// на индексы каналов, менять их вручную нельзя.
	System  bool   `json:"system" plan:"Система" sensitivity:"public"`
	Comment string `json:"comment,omitempty" plan:"Комментарий" sensitivity:"public"`
}

// RouteRule — правило выбора таблицы (ip rule).
type RouteRule struct {
	ID      string `json:"id" plan:"Идентификатор" sensitivity:"public" identity:"true"`
	Name    string `json:"name" plan:"Название" sensitivity:"public"`
	Enabled bool   `json:"enabled" plan:"Состояние" sensitivity:"public" format:"switch"`
	// Priority — чем меньше, тем раньше правило проверяется.
	Priority int `json:"priority" plan:"Приоритет" sensitivity:"public"`
	// Селекторы: пустое поле означает «любой».
	From      string `json:"from,omitempty" plan:"Источник" sensitivity:"public"`
	To        string `json:"to,omitempty" plan:"Назначение" sensitivity:"public"`
	FwMark    string `json:"fwmark,omitempty" plan:"Метка трафика" sensitivity:"public"`
	Interface string `json:"interface,omitempty" plan:"Интерфейс" sensitivity:"public"`
	// Table — куда направить совпавший трафик.
	Table   string `json:"table" plan:"Таблица" sensitivity:"public"`
	System  bool   `json:"system" plan:"Система" sensitivity:"public"`
	Comment string `json:"comment,omitempty" plan:"Комментарий" sensitivity:"public"`
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
	Enabled bool            `json:"enabled" plan:"Состояние" sensitivity:"public" format:"switch"`
	IPSets  []FirewallIPSet `json:"ipsets,omitempty" plan:"Наборы адресов" sensitivity:"public"`
	// Zones задают политику по умолчанию для трафика, не совпавшего ни с одним
	// правилом зоны. Политика зоны действует на вход и на форвард.
	Zones []Zone `json:"zones" plan:"Зоны" sensitivity:"public"`
	// OutputPolicy — что делать с трафиком самого роутера, не совпавшим ни с
	// одним правилом. Вынесено отдельно от зон намеренно: запретить роутеру
	// исходящие — решение куда более серьёзное, чем закрыть вход, и прятать
	// его в общую политику зоны нельзя.
	OutputPolicy string `json:"output_policy" plan:"Политика исходящего трафика" sensitivity:"public"`
	// Rules — единый упорядоченный список правил.
	Rules []FirewallRule `json:"rules" plan:"Правила" sensitivity:"public"`
	// NAT — трансляция адресов: и подмена источника на выходе, и проброс
	// портов внутрь. Это две стороны одного механизма, и держать их в разных
	// разделах панели было ошибкой.
	NAT []NATRule `json:"nat" plan:"NAT" sensitivity:"public"`
}

// FirewallIPSet is a user-maintained IPv4 address/prefix selector.
type FirewallIPSet struct {
	ID      string   `json:"id" plan:"Идентификатор" sensitivity:"public" identity:"true"`
	Name    string   `json:"name" plan:"Название" sensitivity:"public"`
	Entries []string `json:"entries" plan:"Записи" sensitivity:"public"`
}

// Zone — группа интерфейсов с общей политикой.
type Zone struct {
	Name        string `json:"name" plan:"Название" sensitivity:"public"` // lan | wan | vpn
	Title       string `json:"title" plan:"Название" sensitivity:"public"`
	Description string `json:"description,omitempty" plan:"Описание" sensitivity:"public"`
	// Policy — что делать с пакетом, не совпавшим ни с одним правилом зоны.
	Policy string `json:"policy" plan:"Политика" sensitivity:"public"` // accept | drop | reject
	// MSSClamp чинит проблемы с MTU на PPPoE и туннелях.
	MSSClamp bool `json:"mss_clamp" plan:"Коррекция MSS" sensitivity:"public"`
}

// FirewallRule — одно правило. Порядок в списке = порядок в цепочке.
type FirewallRule struct {
	ID      string `json:"id" plan:"Идентификатор" sensitivity:"public" identity:"true"`
	Name    string `json:"name" plan:"Название" sensitivity:"public"`
	Enabled bool   `json:"enabled" plan:"Состояние" sensitivity:"public" format:"switch"`
	// System — правило создано netOS. Удалению не подлежит, выключению — да.
	System bool `json:"system" plan:"Система" sensitivity:"public"`
	// Zone — цепочка, в которую попадает правило: определяется зоной входящего
	// интерфейса.
	Zone string `json:"zone" plan:"Зона" sensitivity:"public"`
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
	Flow string `json:"flow" plan:"Режим flow" sensitivity:"public"`
	// DstZone задаёт зону выходного интерфейса и осмысленна только для
	// форварда: у входа и выхода второй зоны просто нет.
	DstZone string `json:"dst_zone,omitempty" plan:"Зона назначения" sensitivity:"public"`
	Action  string `json:"action" plan:"Действие" sensitivity:"public"` // accept | drop | reject | continue
	// Селекторы. Пустое поле означает «любой».
	Interface    string    `json:"interface,omitempty" plan:"Интерфейс" sensitivity:"public"`
	OutInterface string    `json:"out_interface,omitempty" plan:"Выходной интерфейс" sensitivity:"public"` // Forward output; Interface remains the input selector.
	Protocol     string    `json:"protocol,omitempty" plan:"Протокол" sensitivity:"public"`
	SrcIP        string    `json:"src_ip,omitempty" plan:"Адрес источника" sensitivity:"public"`
	DstIP        string    `json:"dst_ip,omitempty" plan:"Адрес назначения" sensitivity:"public"`
	SrcIPSet     string    `json:"src_ipset,omitempty" plan:"Набор адресов источника" sensitivity:"public"`
	DstIPSet     string    `json:"dst_ipset,omitempty" plan:"Набор адресов назначения" sensitivity:"public"`
	SrcMAC       string    `json:"src_mac,omitempty" plan:"MAC источника" sensitivity:"public"`
	SrcPort      string    `json:"src_port,omitempty" plan:"Порт источника" sensitivity:"public"`
	DstPort      string    `json:"dst_port,omitempty" plan:"Порт назначения" sensitivity:"public"`
	ConnState    string    `json:"conn_state,omitempty" plan:"Состояния соединения" sensitivity:"public"` // new,established,related,invalid
	Schedule     *Schedule `json:"schedule,omitempty" plan:"Расписание" sensitivity:"public"`
	Log          bool      `json:"log" plan:"Журналирование" sensitivity:"public"`
	Comment      string    `json:"comment,omitempty" plan:"Комментарий" sensitivity:"public"`
}

type Schedule struct {
	// TimeStart and TimeStop are UTC. The iptables kernel-timezone mode is
	// deliberately not used: its offset is commonly unset and is not kept in
	// sync with daylight-saving transitions by Linux distributions.
	Days      []string `json:"days" plan:"Дни недели" sensitivity:"public"`
	TimeStart string   `json:"time_start" plan:"Время начала" sensitivity:"public"`
	TimeStop  string   `json:"time_stop" plan:"Время окончания" sensitivity:"public"`
}

// NATRule — правило трансляции адресов.
//
// Направление source подменяет адрес отправителя на выходе из роутера: это
// то, благодаря чему клиенты локальной сети видны в интернете как сам роутер.
// Направление destination подменяет адрес получателя на входе: обращение
// снаружи на порт роутера уезжает на устройство внутри сети.
type NATRule struct {
	ID      string `json:"id" plan:"Идентификатор" sensitivity:"public" identity:"true"`
	Name    string `json:"name" plan:"Название" sensitivity:"public"`
	Enabled bool   `json:"enabled" plan:"Состояние" sensitivity:"public" format:"switch"`
	System  bool   `json:"system" plan:"Система" sensitivity:"public"`
	// Direction: source (подмена отправителя) | destination (проброс внутрь).
	Direction string `json:"direction" plan:"Направление" sensitivity:"public"`

	// --- подмена отправителя ---
	//
	// Interface — через какой интерфейс уходит трафик. Задаётся именно
	// интерфейс, а не зона: в ядре правило всё равно привязано к интерфейсу,
	// и лишний слой абстракции только мешает понять, что произойдёт.
	Interface string `json:"interface,omitempty" plan:"Интерфейс" sensitivity:"public"`
	// Source ограничивает правило отправителями из этой подсети.
	Source string `json:"source,omitempty" plan:"Источник" sensitivity:"public"`
	// ToSource — адрес, на который подменять. Пусто означает маскарад:
	// подставится текущий адрес интерфейса, что и нужно на динамическом
	// подключении, где адрес меняется.
	ToSource string `json:"to_source,omitempty" plan:"Подмена адреса источника" sensitivity:"public"`

	// --- проброс внутрь ---
	Protocol string `json:"protocol,omitempty" plan:"Протокол" sensitivity:"public"`
	// ExtPort — порт, на который обращаются снаружи.
	ExtPort string `json:"ext_port,omitempty" plan:"Внешний порт" sensitivity:"public"`
	// DestIP и DestPort — куда перенаправить.
	DestIP   string `json:"dest_ip,omitempty" plan:"Адрес назначения" sensitivity:"public"`
	DestPort string `json:"dest_port,omitempty" plan:"Порт назначения" sensitivity:"public"`
	// AllowFrom ограничивает, с каких адресов принимать обращения.
	AllowFrom string `json:"allow_from,omitempty" plan:"Разрешённые источники" sensitivity:"public"`

	Comment string `json:"comment,omitempty" plan:"Комментарий" sensitivity:"public"`
}

// ---------------------------------------------------------------------------
// DHCP
// ---------------------------------------------------------------------------

type DHCP struct {
	// Provider выбирается в разделе компонентов: здесь только то, что
	// относится к самой выдаче адресов.
	Provider        string        `json:"provider" plan:"Служба" sensitivity:"public"`
	Enabled         bool          `json:"enabled" plan:"Состояние" sensitivity:"public" format:"switch"`
	Reservations    []Reservation `json:"reservations" plan:"Закреплённые адреса DHCP" sensitivity:"public"`
	AdvancedOptions string        `json:"advanced_options,omitempty" plan:"Дополнительные параметры" sensitivity:"secret"`
}

type DHCPPool struct {
	Enabled    bool              `json:"enabled" plan:"Состояние" sensitivity:"public" format:"switch"`
	Start      string            `json:"start" plan:"Начало диапазона" sensitivity:"public"`
	End        string            `json:"end" plan:"Конец диапазона" sensitivity:"public"`
	LeaseTime  int               `json:"lease_time" plan:"Срок аренды" sensitivity:"public"`
	DNSServers []string          `json:"dns_servers,omitempty" plan:"DNS-серверы" sensitivity:"public"`
	Gateway    string            `json:"gateway,omitempty" plan:"Шлюз" sensitivity:"public"`
	Domain     string            `json:"domain,omitempty" plan:"Домен" sensitivity:"public"`
	Options    map[string]string `json:"options,omitempty" plan:"Дополнительные параметры" sensitivity:"public"`
}

type Reservation struct {
	ID       string `json:"id" plan:"Идентификатор" sensitivity:"public" identity:"true"`
	Enabled  bool   `json:"enabled" plan:"Состояние" sensitivity:"public" format:"switch"`
	MAC      string `json:"mac" plan:"MAC-адрес" sensitivity:"public"`
	IP       string `json:"ip" plan:"IP-адрес" sensitivity:"public"`
	Hostname string `json:"hostname,omitempty" plan:"Имя устройства" sensitivity:"public"`
	Network  string `json:"network" plan:"Локальная сеть" sensitivity:"public"`
	Comment  string `json:"comment,omitempty" plan:"Комментарий" sensitivity:"public"`
}

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------

type DNS struct {
	Provider         string         `json:"provider" plan:"Служба" sensitivity:"public"`
	Enabled          bool           `json:"enabled" plan:"Состояние" sensitivity:"public" format:"switch"`
	Port             int            `json:"port" plan:"Порт" sensitivity:"public"`
	Upstreams        []Upstream     `json:"upstreams" plan:"Вышестоящие резолверы" sensitivity:"public"`
	Bootstrap        []string       `json:"bootstrap" plan:"DNS для начального подключения" sensitivity:"public"`
	CacheSize        int            `json:"cache_size" plan:"Размер кеша" sensitivity:"public"`
	DNSSEC           bool           `json:"dnssec" plan:"Проверка DNSSEC" sensitivity:"public"`
	LocalDomain      string         `json:"local_domain" plan:"Локальный домен" sensitivity:"public"`
	StaticRecords    []DNSRecord    `json:"static_records" plan:"Статические записи" sensitivity:"public"`
	SplitRules       []DNSSplitRule `json:"split_rules" plan:"Правила разделения трафика" sensitivity:"public"`
	Blocklists       []Blocklist    `json:"blocklists" plan:"Списки блокировки" sensitivity:"public"`
	RebindProtection bool           `json:"rebind_protection" plan:"Защита от DNS rebinding" sensitivity:"public"`
	ForceLocal       bool           `json:"force_local" plan:"Принудительный локальный DNS" sensitivity:"public"`
	QueryLog         bool           `json:"query_log" plan:"Журнал запросов" sensitivity:"public"`
	AdvancedOptions  string         `json:"advanced_options,omitempty" plan:"Дополнительные параметры" sensitivity:"secret"`
}

type Upstream struct {
	ID      string `json:"id" plan:"Идентификатор" sensitivity:"public" identity:"true"`
	Type    string `json:"type" plan:"Тип" sensitivity:"public"` // plain | dot | doh | doq
	Address string `json:"address" plan:"Адрес" sensitivity:"public"`
	Channel string `json:"channel,omitempty" plan:"Канал" sensitivity:"public" reference:"channel"`
	Enabled bool   `json:"enabled" plan:"Состояние" sensitivity:"public" format:"switch"`
	Comment string `json:"comment,omitempty" plan:"Комментарий" sensitivity:"public"`
}

type DNSRecord struct {
	ID    string `json:"id" plan:"Идентификатор" sensitivity:"public" identity:"true"`
	Type  string `json:"type" plan:"Тип" sensitivity:"public"`
	Name  string `json:"name" plan:"Название" sensitivity:"public"`
	Value string `json:"value" plan:"Значение" sensitivity:"public"`
}

type DNSSplitRule struct {
	ID       string   `json:"id" plan:"Идентификатор" sensitivity:"public" identity:"true"`
	Domains  []string `json:"domains" plan:"Домены" sensitivity:"public"`
	Upstream string   `json:"upstream,omitempty" plan:"Вышестоящий резолвер" sensitivity:"public"`
	Channel  string   `json:"channel,omitempty" plan:"Канал" sensitivity:"public" reference:"channel"`
	Enabled  bool     `json:"enabled" plan:"Состояние" sensitivity:"public" format:"switch"`
}

type Blocklist struct {
	ID      string `json:"id" plan:"Идентификатор" sensitivity:"public" identity:"true"`
	Name    string `json:"name" plan:"Название" sensitivity:"public"`
	URL     string `json:"url" plan:"URL" sensitivity:"secret"`
	CAFile  string `json:"ca_file,omitempty" plan:"Файл центра сертификации" sensitivity:"public"`
	Enabled bool   `json:"enabled" plan:"Состояние" sensitivity:"public" format:"switch"`
}

// ---------------------------------------------------------------------------
// Клиенты
// ---------------------------------------------------------------------------

type Client struct {
	ID       string `json:"id" plan:"Идентификатор" sensitivity:"public" identity:"true"`
	MAC      string `json:"mac" plan:"MAC-адрес" sensitivity:"public"`
	Name     string `json:"name" plan:"Название" sensitivity:"public"`
	Network  string `json:"network,omitempty" plan:"Локальная сеть" sensitivity:"public"`
	Channel  string `json:"channel,omitempty" plan:"Канал" sensitivity:"public" reference:"channel"`
	Blocked  bool   `json:"blocked" plan:"Блокировка" sensitivity:"public"`
	DownKbit int    `json:"down_kbit" plan:"Загрузка, Мбит/с" sensitivity:"public" format:"mbit"`
	UpKbit   int    `json:"up_kbit" plan:"Отдача, Мбит/с" sensitivity:"public" format:"mbit"`
	Comment  string `json:"comment,omitempty" plan:"Комментарий" sensitivity:"public"`
}

// ---------------------------------------------------------------------------
// Каналы и политики
// ---------------------------------------------------------------------------

type Channel struct {
	SecretsSet map[string]bool `json:"secrets_set,omitempty" plan:"-" sensitivity:"secret"` // Read response metadata, stripped before saving.

	ID       string         `json:"id" plan:"Идентификатор" sensitivity:"public" identity:"true"`
	Index    int            `json:"index" plan:"Номер" sensitivity:"public"`
	Name     string         `json:"name" plan:"Название" sensitivity:"public"`
	Enabled  bool           `json:"enabled" plan:"Состояние" sensitivity:"public" format:"switch"`
	Type     string         `json:"type" plan:"Тип" sensitivity:"public"`   // direct | wireguard | xray | openconnect | l2tp | ikev2
	Mode     string         `json:"mode" plan:"Режим" sensitivity:"public"` // tun | tproxy | socks
	FailMode string         `json:"fail_mode" plan:"Действие при отказе" sensitivity:"public"`
	Fallback string         `json:"fallback,omitempty" plan:"Запасной канал" sensitivity:"public" reference:"channel"`
	Probe    Probe          `json:"probe" plan:"Проверка канала" sensitivity:"public"`
	Config   map[string]any `json:"config,omitempty" plan:"Параметры подключения" sensitivity:"public"`
}

type Policy struct {
	ID        string    `json:"id" plan:"Идентификатор" sensitivity:"public" identity:"true"`
	Name      string    `json:"name" plan:"Название" sensitivity:"public"`
	Enabled   bool      `json:"enabled" plan:"Состояние" sensitivity:"public" format:"switch"`
	Priority  int       `json:"priority" plan:"Приоритет" sensitivity:"public"`
	Channel   string    `json:"channel" plan:"Канал" sensitivity:"public" reference:"channel"`
	SrcIP     string    `json:"src_ip,omitempty" plan:"Адрес источника" sensitivity:"public"`
	SrcMAC    string    `json:"src_mac,omitempty" plan:"MAC источника" sensitivity:"public"`
	Network   string    `json:"network,omitempty" plan:"Локальная сеть" sensitivity:"public"`
	VPNServer string    `json:"vpn_server,omitempty" plan:"VPN-сервер" sensitivity:"public"`
	VPNPeer   string    `json:"vpn_peer,omitempty" plan:"VPN-клиент" sensitivity:"public"`
	Protocol  string    `json:"protocol,omitempty" plan:"Протокол" sensitivity:"public"`
	DstPort   string    `json:"dst_port,omitempty" plan:"Порт назначения" sensitivity:"public"`
	DstIP     string    `json:"dst_ip,omitempty" plan:"Адрес назначения" sensitivity:"public"`
	Domains   []string  `json:"domains,omitempty" plan:"Домены" sensitivity:"public"`
	Schedule  *Schedule `json:"schedule,omitempty" plan:"Расписание" sensitivity:"public"`
	Comment   string    `json:"comment,omitempty" plan:"Комментарий" sensitivity:"public"`
}

type VPNServer struct {
	Isolated   bool            `json:"isolated" plan:"Изоляция" sensitivity:"public"`       // Block access to and from other LAN/VPN segments.
	SecretsSet map[string]bool `json:"secrets_set,omitempty" plan:"-" sensitivity:"secret"` // Read response metadata, stripped before saving.

	RealityKeySet  bool           `json:"reality_key_set,omitempty" plan:"-" sensitivity:"public"` // Read response metadata; never a credential.
	ID             string         `json:"id" plan:"Идентификатор" sensitivity:"public" identity:"true"`
	Index          int            `json:"index" plan:"Номер" sensitivity:"public"`
	Name           string         `json:"name" plan:"Название" sensitivity:"public"`
	Enabled        bool           `json:"enabled" plan:"Состояние" sensitivity:"public" format:"switch"`
	Type           string         `json:"type" plan:"Тип" sensitivity:"public"`
	Subnet         string         `json:"subnet" plan:"Подсеть" sensitivity:"public"`
	Port           int            `json:"port" plan:"Порт" sensitivity:"public"`
	DefaultChannel string         `json:"default_channel,omitempty" plan:"Канал выхода по умолчанию" sensitivity:"public" reference:"channel"`
	Peers          []VPNPeer      `json:"peers" plan:"VPN-клиенты" sensitivity:"public"`
	Config         map[string]any `json:"config,omitempty" plan:"Параметры подключения" sensitivity:"public"`
}

type VPNPeer struct {
	TLSFingerprint string          `json:"tls_fingerprint,omitempty" plan:"Отпечаток TLS" sensitivity:"public"`
	SecretsSet     map[string]bool `json:"secrets_set,omitempty" plan:"-" sensitivity:"secret"` // Read response metadata, stripped before saving.

	WireGuardProfile *WireGuardClientProfile `json:"wireguard_profile,omitempty" plan:"Профиль WireGuard" sensitivity:"public"`
	ID               string                  `json:"id" plan:"Идентификатор" sensitivity:"public" identity:"true"`
	Name             string                  `json:"name" plan:"Название" sensitivity:"public"`
	Enabled          bool                    `json:"enabled" plan:"Состояние" sensitivity:"public" format:"switch"`
	Address          string                  `json:"address" plan:"Адрес" sensitivity:"public"`
	Channel          string                  `json:"channel,omitempty" plan:"Канал" sensitivity:"public" reference:"channel"`
	Credentials      map[string]string       `json:"credentials,omitempty" plan:"Учётные данные" sensitivity:"public"`
	Comment          string                  `json:"comment,omitempty" plan:"Комментарий" sensitivity:"public"`
}

// ---------------------------------------------------------------------------
// Wi-Fi
// ---------------------------------------------------------------------------

type WiFiRadio struct {
	ID      string     `json:"id" plan:"Идентификатор" sensitivity:"public" identity:"true"`
	Device  string     `json:"device" plan:"Устройство" sensitivity:"public"`
	Enabled bool       `json:"enabled" plan:"Состояние" sensitivity:"public" format:"switch"`
	Band    string     `json:"band" plan:"Диапазон" sensitivity:"public"`
	Channel int        `json:"channel" plan:"Канал" sensitivity:"public" reference:"channel"`
	Width   int        `json:"width" plan:"Ширина канала" sensitivity:"public"`
	Country string     `json:"country" plan:"Страна" sensitivity:"public"`
	TxPower int        `json:"tx_power,omitempty" plan:"Мощность передатчика" sensitivity:"public"`
	SSIDs   []WiFiSSID `json:"ssids" plan:"Сети Wi-Fi" sensitivity:"public"`
}

type WiFiSSID struct {
	SecretsSet map[string]bool `json:"secrets_set,omitempty" plan:"-" sensitivity:"secret"` // Read response metadata, stripped before saving.

	ID       string `json:"id" plan:"Идентификатор" sensitivity:"public" identity:"true"`
	SSID     string `json:"ssid" plan:"Имя сети Wi-Fi" sensitivity:"public"`
	Enabled  bool   `json:"enabled" plan:"Состояние" sensitivity:"public" format:"switch"`
	Security string `json:"security" plan:"Защита" sensitivity:"public"`
	Password string `json:"password,omitempty" plan:"Пароль" sensitivity:"secret"`
	Network  string `json:"network" plan:"Локальная сеть" sensitivity:"public"`
	Hidden   bool   `json:"hidden" plan:"Скрытая сеть" sensitivity:"public"`
	Isolate  bool   `json:"isolate" plan:"Изоляция" sensitivity:"public"`
}
