
import { Hono } from 'hono';
import { z } from 'zod';
import type { App } from '../types';
import { auditStatement, requireRecent } from '../core/security';
import {
  body, date, employeeSchema, login, parse,
  password, scheduleSchema, uuid
} from '../core/validation';
import { ensure } from '../core/errors';
import {
  encryptPersonal, hashPassword, randomToken, sha256
} from '../core/crypto';
import { localDate, scheduleMinutes } from '../core/time';

export const adminEmployees = new Hono<App>();

const notCancelled = (alias: string) =>
  `NOT EXISTS (
    SELECT 1 FROM schedule_assignment_cancellations cac
    WHERE cac.assignment_id=${alias}.id
  )`;

adminEmployees.get('/employees', async c => {
  const db = c.get('db');
  const settings = await db.prepare(
    'SELECT timezone FROM settings WHERE id=1'
  ).first<{timezone:string}>();

  const today = localDate(Date.now(), settings!.timezone);

  const rows = await db.prepare(`
    SELECT e.*,u.id user_id,u.login,u.email,
           u.active user_active,u.must_change_password,
      (
        SELECT s.name
        FROM schedule_assignments a
        JOIN schedules s ON s.id=a.schedule_id
        WHERE a.employee_id=e.id
          AND a.effective_from<=?
          AND ${notCancelled('a')}
        ORDER BY a.effective_from DESC
        LIMIT 1
      ) schedule_name
    FROM employees e
    JOIN users u ON u.employee_id=e.id
    ORDER BY e.full_name
  `).bind(today).all<any>();

  return c.json(
    rows.results.map(({cpf_encrypted,...r})=>r)
  );
});

adminEmployees.post('/employees', async c => {
  const input = await body(
    c,
    employeeSchema.extend({
      initial_password:password,
      schedule_id:uuid
    }).strict()
  );

  const db=c.get('db');
  const now=Date.now();
  const employeeId=crypto.randomUUID();
  const userId=crypto.randomUUID();

  const exists=await db.prepare(
    'SELECT id FROM schedules WHERE id=? AND archived=0'
  ).bind(input.schedule_id).first();

  ensure(
    exists,422,'invalid_schedule',
    'Selecione uma jornada válida.'
  );

  const end=input.employment_end||null;

  ensure(
    input.status!=='terminated'||end,
    422,'employment_end_required',
    'Informe a data de desligamento.'
  );

  ensure(
    !end||end>=input.admission_date,
    422,'invalid_employment_end',
    'O desligamento deve ser posterior à admissão.'
  );

  const hash=await hashPassword(
    input.initial_password,c.env.AUTH_PEPPER
  );

  const cpf=input.cpf
