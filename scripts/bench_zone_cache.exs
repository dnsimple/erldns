# Times the zone cache lookups a query makes, through the public API, against the same lookups as
# of another git ref. From the repository root, after `rebar3 compile`:
#
#     elixir scripts/bench_zone_cache.exs [Zones] [Ref]
#
# Ref defaults to `main`. Its erldns_zone_cache is compiled under another name and reads the same
# tables. Each zone has an apex with 6 types and 30 names of 1 or 2 labels with A and AAAA, and
# every call picks a name at random.
Mix.install([{:benchee, "~> 1.5"}])

Code.prepend_paths(Path.wildcard("_build/default/lib/*/ebin"))

defmodule ZoneCacheBench do
  require Record

  @records "dns_erlang/include/dns_records.hrl"
  for name <-
        [:dns_rr, :dns_rrdata_a, :dns_rrdata_aaaa, :dns_rrdata_mx] ++
          [:dns_rrdata_ns, :dns_rrdata_soa, :dns_rrdata_txt] do
    Record.defrecordp(name, Record.extract(name, from_lib: @records))
  end

  Record.defrecordp(:zone, Record.extract(:zone, from_lib: "erldns/include/erldns.hrl"))

  @baseline :erldns_zone_cache_baseline
  @a 1
  @ns 2
  @soa 6
  @mx 15
  @txt 16
  @aaaa 28

  # One fun per module, with `m` replaced by the module at compile time: a call through a variable
  # is a dynamic apply, which would add the same cost to both sides.
  defmacrop both(fun) do
    for mod <- [@baseline, :erldns_zone_cache] do
      Macro.prewalk(fun, fn
        {:m, _, ctx} when is_atom(ctx) -> mod
        ast -> ast
      end)
    end
  end

  def run(num_zones, ref) do
    load_baseline(ref)
    :rand.seed(:exsss, {1, 2, 3})
    {:ok, _} = Application.ensure_all_started(:telemetry)
    :logger.set_primary_config(:level, :error)
    {:ok, _} = :erldns_zone_cache.start_link()
    zones = Enum.map(1..num_zones, &put_zone/1)

    IO.puts(
      "#{num_zones} zones, #{:ets.info(:erldns_zone_records_typed, :size)} rows, " <>
        "#{(:ets.info(:erldns_zone_records_typed, :memory) * 8) |> div(1_000_000)} MB, " <>
        "#{String.trim(elem(System.cmd("git", ["describe", "--always", "--dirty"]), 0))} against #{ref}"
    )

    names = for {z, ls} <- zones, l <- ls, do: {z, l}
    leaf = List.to_tuple(names)
    missing = List.to_tuple(for {z, l} <- names, do: {z, ["nope" | l]})
    ent = List.to_tuple(for {z, [_, _ | _] = l} <- names, do: {z, tl(l)})

    cases = [
      {"get_zonecut, no cut", leaf, both(fn {z, l} -> m.get_zonecut(z, l) end)},
      {"typed fetch, present (A)", leaf,
       both(fn {z, l} -> m.get_records_by_name_and_type(z, l, @a) end)},
      {"typed fetch, absent (NS)", leaf,
       both(fn {z, l} -> m.get_records_by_name_and_type(z, l, @ns) end)},
      {"is_name_in_zone, yes", leaf, both(fn {z, l} -> m.is_name_in_zone(z, l) end)},
      {"is_name_in_zone, no", missing, both(fn {z, l} -> m.is_name_in_zone(z, l) end)},
      {"zone_name_existence, ent", ent, both(fn {z, l} -> m.zone_name_existence(z, l) end)},
      {"zone_name_existence, nxdomain", missing,
       both(fn {z, l} -> m.zone_name_existence(z, l) end)},
      {"resolved A, exact", leaf,
       both(fn {z, l} -> m.get_records_by_name_and_type_resolved(z, l, @a) end)},
      {"resolved MX, no data", leaf,
       both(fn {z, l} -> m.get_records_by_name_and_type_resolved(z, l, @mx) end)},
      {"resolved A, ent", ent,
       both(fn {z, l} -> m.get_records_by_name_and_type_resolved(z, l, @a) end)},
      {"resolved A, nxdomain", missing,
       both(fn {z, l} -> m.get_records_by_name_and_type_resolved(z, l, @a) end)}
    ]

    for {name, queries, [base, this]} <- cases, i <- 0..999 do
      q = elem(queries, i)
      base.(q) == this.(q) or raise "#{name} differs on #{inspect(q)}"
    end

    for {name, queries, [base, this]} <- cases do
      Benchee.run(%{ref => base, "this tree" => this},
        inputs: [{name, queries}],
        before_each: fn queries -> elem(queries, :rand.uniform(tuple_size(queries)) - 1) end,
        warmup: 1,
        time: 5
      )
    end
  end

  # Compiles the cache module as of the ref under another name; its lookups read the same tables.
  defp load_baseline(ref) do
    {source, 0} = System.cmd("git", ["show", "#{ref}:src/zones/erldns_zone_cache.erl"])
    file = Path.join(System.tmp_dir!(), "#{@baseline}.erl")
    File.write!(file, source)
    {:ok, forms} = :epp.parse_file(String.to_charlist(file), [])

    forms =
      Enum.map(forms, fn
        {:attribute, anno, :module, :erldns_zone_cache} -> {:attribute, anno, :module, @baseline}
        form -> form
      end)

    {:ok, @baseline, bin} = :compile.forms(forms, [:binary, :return_errors])
    {:module, @baseline} = :code.load_binary(@baseline, String.to_charlist(file), bin)
  end

  # Returns the zone's header and the labels of its names below the apex.
  defp put_zone(i) do
    zone_name = "zone#{i}.com"
    names = Enum.uniq(Enum.sort(for _ <- 1..30, do: label_path()))

    soa =
      dns_rrdata_soa(
        mname: "ns1." <> zone_name,
        rname: "admin." <> zone_name,
        serial: 1,
        refresh: 3600,
        retry: 600,
        expire: 86400,
        minimum: 300
      )

    apex = [
      rr(zone_name, @soa, soa),
      rr(zone_name, @ns, dns_rrdata_ns(dname: "ns1." <> zone_name)),
      rr(zone_name, @a, dns_rrdata_a(ip: {192, 0, 2, 1})),
      rr(zone_name, @aaaa, dns_rrdata_aaaa(ip: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1})),
      rr(zone_name, @mx, dns_rrdata_mx(preference: 10, exchange: zone_name)),
      rr(zone_name, @txt, dns_rrdata_txt(txt: ["v=spf1 -all"]))
    ]

    records =
      Enum.flat_map(names, fn labels ->
        name = Enum.join(labels ++ [zone_name], ".")

        [
          rr(name, @a, dns_rrdata_a(ip: {192, 0, 2, 2})),
          rr(name, @aaaa, dns_rrdata_aaaa(ip: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 2}))
        ]
      end)

    :ok = :erldns_zone_cache.put_zone({zone_name, "v1", apex ++ records})
    zone(labels: zone_labels) = zone = :erldns_zone_cache.lookup_zone(zone_name)
    {zone, for(labels <- names, do: labels ++ zone_labels)}
  end

  defp rr(name, type, data), do: dns_rr(name: name, type: type, ttl: 3600, data: data)

  defp label_path, do: if(:rand.uniform(3) == 3, do: [label(), label()], else: [label()])

  defp label,
    do: for(_ <- 1..(3 + :rand.uniform(8)), into: "", do: <<?a + :rand.uniform(26) - 1>>)
end

{num_zones, ref} =
  case System.argv() do
    [] -> {10_000, "main"}
    [z] -> {String.to_integer(z), "main"}
    [z, ref] -> {String.to_integer(z), ref}
  end

ZoneCacheBench.run(num_zones, ref)
