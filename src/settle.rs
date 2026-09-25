//! Pure bill-splitting logic: apportioning amounts in integer cents,
//! connectivity of the "who can pay whom" graph, and settlement.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

pub type PersonId = i64;

/// Who can transfer money to whom. `None` means everybody can pay everybody.
pub type Adjacency = Option<HashMap<PersonId, BTreeSet<PersonId>>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
    pub from: PersonId,
    pub to: PersonId,
    pub amount: i64,
}

/// Round `values` to integers so that they sum exactly to `target`,
/// using the largest-remainder method.
pub fn apportion(values: &[f64], target: i64) -> Vec<i64> {
    let mut out: Vec<i64> = values.iter().map(|v| v.floor() as i64).collect();
    let mut diff = target - out.iter().sum::<i64>();
    if values.is_empty() {
        return out;
    }
    let mut order: Vec<usize> = (0..values.len()).collect();
    let frac = |i: usize| values[i] - values[i].floor();
    if diff > 0 {
        // Hand out missing units to those with the largest fractional parts.
        order.sort_by(|&a, &b| frac(b).total_cmp(&frac(a)).then(a.cmp(&b)));
        for &i in order.iter().cycle() {
            if diff == 0 {
                break;
            }
            out[i] += 1;
            diff -= 1;
        }
    } else if diff < 0 {
        order.sort_by(|&a, &b| frac(a).total_cmp(&frac(b)).then(a.cmp(&b)));
        for &i in order.iter().cycle() {
            if diff == 0 {
                break;
            }
            out[i] -= 1;
            diff += 1;
        }
    }
    out
}

/// Split `total` cents proportionally to `weights`.
pub fn split_by_weights(total: i64, weights: &[f64]) -> Vec<i64> {
    let sum: f64 = weights.iter().sum();
    if sum <= 0.0 {
        return vec![0; weights.len()];
    }
    let exact: Vec<f64> = weights.iter().map(|w| total as f64 * w / sum).collect();
    apportion(&exact, total)
}

fn neighbours<'a>(
    adj: &'a Adjacency,
    nodes: &'a [PersonId],
    p: PersonId,
) -> Box<dyn Iterator<Item = PersonId> + 'a> {
    match adj {
        None => Box::new(nodes.iter().copied().filter(move |&q| q != p)),
        Some(map) => Box::new(map.get(&p).into_iter().flatten().copied()),
    }
}

/// Connected components of the payment graph, restricted to `nodes`.
pub fn components(nodes: &[PersonId], adj: &Adjacency) -> Vec<Vec<PersonId>> {
    let mut seen = BTreeSet::new();
    let mut comps = Vec::new();
    for &start in nodes {
        if !seen.insert(start) {
            continue;
        }
        let mut comp = vec![start];
        let mut queue = VecDeque::from([start]);
        while let Some(p) = queue.pop_front() {
            for q in neighbours(adj, nodes, p) {
                if seen.insert(q) {
                    comp.push(q);
                    queue.push_back(q);
                }
            }
        }
        comp.sort();
        comps.push(comp);
    }
    comps
}

/// BFS from `start`; returns parent pointers for every reachable node.
fn bfs(start: PersonId, nodes: &[PersonId], adj: &Adjacency) -> HashMap<PersonId, PersonId> {
    let mut parent = HashMap::from([(start, start)]);
    let mut queue = VecDeque::from([start]);
    while let Some(p) = queue.pop_front() {
        for q in neighbours(adj, nodes, p) {
            if let std::collections::hash_map::Entry::Vacant(e) = parent.entry(q) {
                e.insert(p);
                queue.push_back(q);
            }
        }
    }
    parent
}

fn path_to(parent: &HashMap<PersonId, PersonId>, end: PersonId) -> Vec<PersonId> {
    let mut path = vec![end];
    let mut cur = end;
    while parent[&cur] != cur {
        cur = parent[&cur];
        path.push(cur);
    }
    path.reverse();
    path
}

/// Compute transfers that bring every balance to zero.
///
/// `balances`: positive = person is owed money, negative = person owes money.
/// Transfers only go along edges of `adj`; when a debtor and creditor cannot
/// pay each other directly, the money is routed through intermediaries.
/// Returns the transfers and any balances that could not be settled
/// (only non-empty when the payment graph is disconnected).
pub fn settle(
    balances: &BTreeMap<PersonId, i64>,
    adj: &Adjacency,
) -> (Vec<Transfer>, BTreeMap<PersonId, i64>) {
    let nodes: Vec<PersonId> = balances.keys().copied().collect();
    let mut bal = balances.clone();
    let mut flows: BTreeMap<(PersonId, PersonId), i64> = BTreeMap::new();

    loop {
        let debtors: Vec<PersonId> = bal.iter().filter(|(_, v)| **v < 0).map(|(k, _)| *k).collect();
        let creditors: BTreeSet<PersonId> =
            bal.iter().filter(|(_, v)| **v > 0).map(|(k, _)| *k).collect();
        if debtors.is_empty() || creditors.is_empty() {
            break;
        }
        // Pick the debtor/creditor pair with the shortest path, preferring
        // the largest transferable amount (fewer transfers overall).
        let mut best: Option<(usize, i64, Vec<PersonId>)> = None;
        for &d in &debtors {
            let parent = bfs(d, &nodes, adj);
            for &c in &creditors {
                if !parent.contains_key(&c) {
                    continue;
                }
                let path = path_to(&parent, c);
                let amount = (-bal[&d]).min(bal[&c]);
                let better = match &best {
                    None => true,
                    Some((len, amt, _)) => {
                        path.len() < *len || (path.len() == *len && amount > *amt)
                    }
                };
                if better {
                    best = Some((path.len(), amount, path));
                }
            }
        }
        let Some((_, amount, path)) = best else { break };
        for hop in path.windows(2) {
            *flows.entry((hop[0], hop[1])).or_default() += amount;
        }
        *bal.get_mut(&path[0]).unwrap() += amount;
        *bal.get_mut(path.last().unwrap()).unwrap() -= amount;
    }

    // Net out opposite flows between the same pair.
    let mut transfers = Vec::new();
    for (&(a, b), &amt) in &flows {
        let back = flows.get(&(b, a)).copied().unwrap_or(0);
        if amt > back {
            transfers.push(Transfer { from: a, to: b, amount: amt - back });
        }
    }
    transfers.sort_by(|x, y| y.amount.cmp(&x.amount).then(x.from.cmp(&y.from)));
    bal.retain(|_, v| *v != 0);
    (transfers, bal)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adj(edges: &[(PersonId, PersonId)]) -> Adjacency {
        let mut m: HashMap<PersonId, BTreeSet<PersonId>> = HashMap::new();
        for &(a, b) in edges {
            m.entry(a).or_default().insert(b);
            m.entry(b).or_default().insert(a);
        }
        Some(m)
    }

    fn check_settles(balances: &BTreeMap<PersonId, i64>, transfers: &[Transfer]) {
        let mut b = balances.clone();
        for t in transfers {
            *b.get_mut(&t.from).unwrap() += t.amount;
            *b.get_mut(&t.to).unwrap() -= t.amount;
        }
        assert!(b.values().all(|v| *v == 0), "not settled: {b:?}");
    }

    #[test]
    fn split_even_with_remainder() {
        let s = split_by_weights(1000, &[1.0, 1.0, 1.0]);
        assert_eq!(s.iter().sum::<i64>(), 1000);
        assert_eq!(s, vec![334, 333, 333]);
    }

    #[test]
    fn split_weighted() {
        assert_eq!(split_by_weights(900, &[2.0, 1.0]), vec![600, 300]);
    }

    #[test]
    fn apportion_zero_sum() {
        let r = apportion(&[10.4, -3.3, -7.1], 0);
        assert_eq!(r.iter().sum::<i64>(), 0);
    }

    #[test]
    fn complete_graph_settles_directly() {
        let b = BTreeMap::from([(1, 300), (2, -100), (3, -200)]);
        let (t, left) = settle(&b, &None);
        assert!(left.is_empty());
        assert_eq!(t.len(), 2);
        check_settles(&b, &t);
    }

    #[test]
    fn routes_through_intermediary() {
        // 1 owes 3, but 1 can only pay 2 and 2 can only pay 3.
        let b = BTreeMap::from([(1, -500), (2, 0), (3, 500)]);
        let (t, left) = settle(&b, &adj(&[(1, 2), (2, 3)]));
        assert!(left.is_empty());
        assert_eq!(
            t,
            vec![
                Transfer { from: 1, to: 2, amount: 500 },
                Transfer { from: 2, to: 3, amount: 500 }
            ]
        );
    }

    #[test]
    fn intermediary_with_own_debt_is_netted() {
        let b = BTreeMap::from([(1, -500), (2, -200), (3, 700)]);
        let (t, left) = settle(&b, &adj(&[(1, 2), (2, 3)]));
        assert!(left.is_empty());
        check_settles(&b, &t);
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn disconnected_graph_leaves_leftovers() {
        let b = BTreeMap::from([(1, -500), (2, 500), (3, -100), (4, 100)]);
        let a = adj(&[(1, 3), (2, 4)]);
        assert_eq!(components(&[1, 2, 3, 4], &a).len(), 2);
        let (_, left) = settle(&b, &a);
        assert!(!left.is_empty());
    }

    #[test]
    fn isolated_person_is_own_component() {
        let a = adj(&[(1, 2)]);
        assert_eq!(components(&[1, 2, 3], &a), vec![vec![1, 2], vec![3]]);
        assert_eq!(components(&[1, 2, 3], &None).len(), 1);
    }
}
