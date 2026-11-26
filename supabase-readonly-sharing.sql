-- MY TRIP: read-only trip sharing
-- Run once in Supabase SQL Editor after the seven MY TRIP data tables exist.

create table if not exists public.trip_shares (
  id uuid primary key default gen_random_uuid(),
  trip_id uuid not null references public.trips(id) on delete cascade,
  owner_id uuid not null references auth.users(id) on delete cascade,
  viewer_id uuid not null references auth.users(id) on delete cascade,
  viewer_email text not null,
  created_at timestamptz not null default now(),
  unique (trip_id, viewer_id)
);
alter table public.trip_shares enable row level security;

-- SECURITY DEFINER helpers avoid recursive RLS policy evaluation.
create or replace function public.is_my_trip_owner(p_trip_id uuid)
returns boolean language sql stable security definer
set search_path = public
as $$
  select exists (
    select 1 from public.trips t
    where t.id = p_trip_id and t.user_id = auth.uid()
  );
$$;

create or replace function public.is_trip_shared_with_me(p_trip_id uuid)
returns boolean language sql stable security definer
set search_path = public
as $$
  select exists (
    select 1 from public.trip_shares s
    where s.trip_id = p_trip_id and s.viewer_id = auth.uid()
  );
$$;

revoke all on function public.is_my_trip_owner(uuid) from public;
revoke all on function public.is_trip_shared_with_me(uuid) from public;
grant execute on function public.is_my_trip_owner(uuid) to authenticated;
grant execute on function public.is_trip_shared_with_me(uuid) to authenticated;

drop policy if exists "Owners manage trip shares" on public.trip_shares;
create policy "Owners manage trip shares"
on public.trip_shares for all to authenticated
using (auth.uid() = owner_id and public.is_my_trip_owner(trip_id))
with check (auth.uid() = owner_id and public.is_my_trip_owner(trip_id));

drop policy if exists "Viewers read their trip shares" on public.trip_shares;
create policy "Viewers read their trip shares"
on public.trip_shares for select to authenticated
using (auth.uid() = viewer_id);

-- Invite an already-registered account by email. This function checks ownership
-- server-side and does not expose the auth.users table to the browser.
create or replace function public.share_trip_with_email(p_trip_id uuid, p_email text)
returns void language plpgsql security definer
set search_path = public, auth
as $$
declare
  v_viewer_id uuid;
  v_owner_id uuid := auth.uid();
begin
  if v_owner_id is null then raise exception 'You must be signed in.'; end if;
  if not exists (
    select 1 from public.trips where id = p_trip_id and user_id = v_owner_id
  ) then raise exception 'Trip not found or you are not the owner.'; end if;

  select id into v_viewer_id from auth.users
  where lower(email) = lower(trim(p_email)) limit 1;

  if v_viewer_id is null then
    raise exception 'No account found for this email. Ask your friend to create an account first.';
  end if;
  if v_viewer_id = v_owner_id then
    raise exception 'You cannot share a trip with your own account.';
  end if;

  insert into public.trip_shares (trip_id, owner_id, viewer_id, viewer_email)
  values (p_trip_id, v_owner_id, v_viewer_id, lower(trim(p_email)))
  on conflict (trip_id, viewer_id)
  do update set viewer_email = excluded.viewer_email;
end;
$$;
revoke all on function public.share_trip_with_email(uuid, text) from public;
grant execute on function public.share_trip_with_email(uuid, text) to authenticated;

-- Viewer gets SELECT only. Existing owner policies continue to govern owner writes.
drop policy if exists "View shared trips" on public.trips;
create policy "View shared trips" on public.trips
for select to authenticated
using (public.is_trip_shared_with_me(id));

drop policy if exists "View shared itinerary" on public.itinerary;
create policy "View shared itinerary" on public.itinerary
for select to authenticated
using (public.is_trip_shared_with_me(trip_id));

drop policy if exists "View shared places" on public.places;
create policy "View shared places" on public.places
for select to authenticated
using (public.is_trip_shared_with_me(trip_id));

drop policy if exists "View shared restaurants" on public.restaurants;
create policy "View shared restaurants" on public.restaurants
for select to authenticated
using (public.is_trip_shared_with_me(trip_id));

drop policy if exists "View shared expenses" on public.expenses;
create policy "View shared expenses" on public.expenses
for select to authenticated
using (public.is_trip_shared_with_me(trip_id));

drop policy if exists "View shared transportation" on public.transportation;
create policy "View shared transportation" on public.transportation
for select to authenticated
using (public.is_trip_shared_with_me(trip_id));

drop policy if exists "View shared accommodation" on public.accommodation;
create policy "View shared accommodation" on public.accommodation
for select to authenticated
using (public.is_trip_shared_with_me(trip_id));

create index if not exists trip_shares_viewer_id_idx on public.trip_shares(viewer_id);
create index if not exists trip_shares_trip_id_idx on public.trip_shares(trip_id);
