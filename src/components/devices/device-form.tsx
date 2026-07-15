"use client"

import { useState, type FormEvent } from "react"
import { useRouter } from "next/navigation"
import { cn } from "@/lib/utils"
import { Card, CardHeader, CardTitle, CardContent, CardFooter } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select } from "@/components/ui/select"

const deviceTypes = [
  { value: "Camera", label: "Camera" },
  { value: "Router", label: "Router" },
  { value: "Speaker", label: "Speaker" },
  { value: "Thermostat", label: "Thermostat" },
  { value: "Smart Plug", label: "Smart Plug" },
  { value: "Light", label: "Light" },
  { value: "Sensor", label: "Sensor" },
  { value: "Media", label: "Media" },
  { value: "Other", label: "Other" },
]

interface DeviceFormProps {
  device?: any
  action: "Create" | "Edit"
}

export function DeviceForm({ device, action }: DeviceFormProps) {
  const router = useRouter()
  const [error, setError] = useState("")
  const [submitting, setSubmitting] = useState(false)

  async function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault()
    setError("")
    setSubmitting(true)

    const form = new FormData(e.currentTarget)
    const body = {
      macAddress: form.get("macAddress"),
      ipAddress: form.get("ipAddress"),
      hostname: form.get("hostname"),
      vendor: form.get("vendor"),
      deviceType: form.get("deviceType"),
      osName: form.get("osName"),
      osVersion: form.get("osVersion"),
      firmwareVersion: form.get("firmwareVersion"),
      openPorts: form.get("openPorts"),
      services: form.get("services"),
    }

    try {
      const url = device ? `/api/devices/${device.id}` : "/api/devices"
      const method = device ? "PUT" : "POST"
      const res = await fetch(url, { method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })

      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.error ?? "Something went wrong")
      }

      router.push("/devices")
      router.refresh()
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save device")
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <form onSubmit={handleSubmit}>
      <Card className="mx-auto max-w-2xl">
        <CardHeader>
          <CardTitle>{action} Device</CardTitle>
        </CardHeader>

        <CardContent className="space-y-5">
          {error && (
            <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950/40 dark:text-red-400">
              {error}
            </div>
          )}

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="macAddress">MAC Address *</Label>
              <Input
                id="macAddress"
                name="macAddress"
                defaultValue={device?.macAddress ?? ""}
                placeholder="00:1A:2B:3C:4D:5E"
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="ipAddress">IP Address *</Label>
              <Input
                id="ipAddress"
                name="ipAddress"
                defaultValue={device?.ipAddress ?? ""}
                placeholder="192.168.1.100"
                required
              />
            </div>
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="hostname">Hostname</Label>
              <Input
                id="hostname"
                name="hostname"
                defaultValue={device?.hostname ?? ""}
                placeholder="office-camera-01"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="vendor">Vendor</Label>
              <Input
                id="vendor"
                name="vendor"
                defaultValue={device?.vendor ?? ""}
                placeholder="Cisco, Ring, etc."
              />
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="deviceType">Device Type</Label>
            <Select
              id="deviceType"
              name="deviceType"
              options={deviceTypes}
              placeholder="Select a type"
              defaultValue={device?.deviceType ?? ""}
            />
          </div>

          <div className="grid gap-4 sm:grid-cols-3">
            <div className="space-y-2">
              <Label htmlFor="osName">OS Name</Label>
              <Input
                id="osName"
                name="osName"
                defaultValue={device?.osName ?? ""}
                placeholder="Linux, Windows, etc."
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="osVersion">OS Version</Label>
              <Input
                id="osVersion"
                name="osVersion"
                defaultValue={device?.osVersion ?? ""}
                placeholder="5.15.0"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="firmwareVersion">Firmware Version</Label>
              <Input
                id="firmwareVersion"
                name="firmwareVersion"
                defaultValue={device?.firmwareVersion ?? ""}
                placeholder="v2.1.4"
              />
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="openPorts">Open Ports</Label>
            <textarea
              id="openPorts"
              name="openPorts"
              defaultValue={device?.openPorts ?? ""}
              placeholder="80, 443, 22, 8080"
              className="flex min-h-[80px] w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 text-sm text-zinc-900 placeholder:text-zinc-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-zinc-400 focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 dark:border-zinc-700 dark:bg-zinc-950 dark:text-zinc-50 dark:placeholder:text-zinc-500 dark:focus-visible:ring-zinc-600"
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="services">Services (JSON)</Label>
            <textarea
              id="services"
              name="services"
              defaultValue={device?.services ?? ""}
              placeholder='[{"port": 80, "name": "HTTP"}]'
              className="flex min-h-[100px] w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 text-sm text-zinc-900 placeholder:text-zinc-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-zinc-400 focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 dark:border-zinc-700 dark:bg-zinc-950 dark:text-zinc-50 dark:placeholder:text-zinc-500 dark:focus-visible:ring-zinc-600"
            />
          </div>
        </CardContent>

        <CardFooter className="justify-between">
          <Button type="button" variant="outline" onClick={() => router.back()}>
            Cancel
          </Button>
          <Button type="submit" disabled={submitting}>
            {submitting ? "Saving..." : action === "Create" ? "Create Device" : "Save Changes"}
          </Button>
        </CardFooter>
      </Card>
    </form>
  )
}
